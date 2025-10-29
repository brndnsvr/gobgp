# GoBGP Crash Fix Implementation Plan

## Objective
Fix critical crash vulnerabilities in GoBGP gRPC API handlers that cause daemon crashes when receiving malformed API requests.

## Analysis Summary
- **Root Cause**: `MustParseAddr()` functions panic on invalid IP addresses from user input
- **Impact**: Any malformed IP address in API requests crashes entire daemon
- **Scope**: 4 critical locations + 1 bounds check + 1 safety net (panic recovery)

## Implementation Strategy

### Phase 1: Code Fixes (Parallel Execution)
1. **Fix grpc_server.go** (3 MustParseAddr calls + 1 bounds check)
   - Line 516: api2Path function - SourceId parsing
   - Line 2330: newGlobalFromAPIStruct - ListenAddresses parsing
   - Line 2336: newGlobalFromAPIStruct - RouterId parsing
   - Line 639: AddPath handler - array bounds check

2. **Fix server.go** (2 MustParseAddr calls)
   - Line 1795: AddBmp handler - Address parsing
   - Line 1811: DeleteBmp handler - Address parsing

3. **Add panic recovery interceptors in main.go**
   - Unary RPC interceptor
   - Stream RPC interceptor
   - Integration with existing interceptor chain

### Phase 2: Testing
1. **Build verification** - Ensure code compiles
2. **Unit tests** - Run existing test suite
3. **Crash scenario testing** - Verify fixes prevent crashes

## Detailed Changes

### Change 1: grpc_server.go Line 513-518 (api2Path function)
**Before:**
```go
if path.SourceAsn != 0 {
    pi = &table.PeerInfo{
        AS: path.SourceAsn,
        ID: netip.MustParseAddr(path.SourceId),
    }
}
```

**After:**
```go
if path.SourceAsn != 0 {
    sourceId, err := netip.ParseAddr(path.SourceId)
    if err != nil {
        return nil, fmt.Errorf("invalid source ID %q: %w", path.SourceId, err)
    }
    pi = &table.PeerInfo{
        AS: path.SourceAsn,
        ID: sourceId,
    }
}
```

### Change 2: grpc_server.go Line 2328-2336 (newGlobalFromAPIStruct)
**Before:**
```go
l := make([]netip.Addr, 0, len(a.ListenAddresses))
for _, addr := range a.ListenAddresses {
    l = append(l, netip.MustParseAddr(addr))
}

global := &oc.Global{
    Config: oc.GlobalConfig{
        As:               a.Asn,
        RouterId:         netip.MustParseAddr(a.RouterId),
        Port:             a.ListenPort,
        LocalAddressList: l,
    },
```

**After:**
```go
l := make([]netip.Addr, 0, len(a.ListenAddresses))
for _, addr := range a.ListenAddresses {
    parsed, err := netip.ParseAddr(addr)
    if err != nil {
        return nil, fmt.Errorf("invalid listen address %q: %w", addr, err)
    }
    l = append(l, parsed)
}

routerId, err := netip.ParseAddr(a.RouterId)
if err != nil {
    return nil, fmt.Errorf("invalid router ID %q: %w", a.RouterId, err)
}

global := &oc.Global{
    Config: oc.GlobalConfig{
        As:               a.Asn,
        RouterId:         routerId,
        Port:             a.ListenPort,
        LocalAddressList: l,
    },
```

### Change 3: grpc_server.go Line 639 (AddPath bounds check)
**Before:**
```go
if err != nil {
    return &api.AddPathResponse{}, err
}

id := path[0].UUID
s.bgpServer.uuidMap[apiutilPathTokey(p)] = id
```

**After:**
```go
if err != nil {
    return &api.AddPathResponse{}, err
}

if len(path) == 0 {
    return &api.AddPathResponse{}, fmt.Errorf("no paths returned from AddPath")
}

id := path[0].UUID
s.bgpServer.uuidMap[apiutilPathTokey(p)] = id
```

### Change 4: server.go Line 1794-1801 (AddBmp)
**Before:**
```go
return s.bmpManager.addServer(&oc.BmpServerConfig{
    Address:               netip.MustParseAddr(r.Address),
    Port:                  port,
    SysName:               sysname,
    SysDescr:              sysDescr,
    RouteMonitoringPolicy: oc.IntToBmpRouteMonitoringPolicyTypeMap[int(r.Policy)],
    StatisticsTimeout:     uint16(r.StatisticsTimeout),
})
```

**After:**
```go
address, err := netip.ParseAddr(r.Address)
if err != nil {
    return fmt.Errorf("invalid BMP server address %q: %w", r.Address, err)
}

return s.bmpManager.addServer(&oc.BmpServerConfig{
    Address:               address,
    Port:                  port,
    SysName:               sysname,
    SysDescr:              sysDescr,
    RouteMonitoringPolicy: oc.IntToBmpRouteMonitoringPolicyTypeMap[int(r.Policy)],
    StatisticsTimeout:     uint16(r.StatisticsTimeout),
})
```

### Change 5: server.go Line 1810-1813 (DeleteBmp)
**Before:**
```go
return s.mgmtOperation(func() error {
    return s.bmpManager.deleteServer(&oc.BmpServerConfig{
        Address: netip.MustParseAddr(r.Address),
        Port:    r.Port,
    })
}, true)
```

**After:**
```go
return s.mgmtOperation(func() error {
    address, err := netip.ParseAddr(r.Address)
    if err != nil {
        return fmt.Errorf("invalid BMP server address %q: %w", r.Address, err)
    }
    return s.bmpManager.deleteServer(&oc.BmpServerConfig{
        Address: address,
        Port:    r.Port,
    })
}, true)
```

### Change 6: main.go - Add panic recovery interceptors
**Location:** After line 219 (after metrics interceptors)

**Add:**
```go
// Add panic recovery interceptors to prevent daemon crashes
unaryPanicRecovery := func(ctx context.Context, req interface{},
    info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
    defer func() {
        if r := recover(); r != nil {
            logger.Error("panic in gRPC unary handler",
                slog.Any("panic", r),
                slog.String("method", info.FullMethod))
            err = fmt.Errorf("internal server error: %v", r)
        }
    }()
    return handler(ctx, req)
}

streamPanicRecovery := func(srv interface{}, ss grpc.ServerStream,
    info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
    defer func() {
        if r := recover(); r != nil {
            logger.Error("panic in gRPC stream handler",
                slog.Any("panic", r),
                slog.String("method", info.FullMethod))
            err = fmt.Errorf("internal server error: %v", r)
        }
    }()
    return handler(srv, ss)
}

// Chain interceptors: panic recovery first, then metrics
if opts.MetricsPath != "" {
    grpcOpts = append(grpcOpts,
        grpc.ChainUnaryInterceptor(unaryPanicRecovery, grpc_prometheus.UnaryServerInterceptor),
        grpc.ChainStreamInterceptor(streamPanicRecovery, grpc_prometheus.StreamServerInterceptor),
    )
} else {
    grpcOpts = append(grpcOpts,
        grpc.UnaryInterceptor(unaryPanicRecovery),
        grpc.StreamInterceptor(streamPanicRecovery),
    )
}
```

## Testing Plan

### 1. Build Verification
```bash
cd /home/bss/code/gobgp
go build -v ./cmd/gobgpd
go build -v ./cmd/gobgp
```

### 2. Unit Tests
```bash
go test -v ./pkg/server/...
```

### 3. Crash Scenario Tests (Manual Verification)
These will require running the daemon and testing with malformed input:
- Invalid source ID in AddPath
- Invalid BMP server address
- Empty path array scenario

## Success Criteria
- ✅ All code compiles without errors
- ✅ All existing tests pass
- ✅ No new test failures introduced
- ✅ Malformed requests return errors instead of crashing daemon

## Risk Assessment
- **Risk Level**: LOW
- **Rationale**:
  - Changes are isolated to error handling paths
  - Converting panics to error returns (safe)
  - No changes to business logic
  - Panic recovery is a safety net only

## Rollback Plan
If issues are detected:
1. Git revert commits
2. Rebuild and redeploy
3. All changes are in 3 files, easy to revert individually

## Execution Order
1. **Parallel**: Fix grpc_server.go and server.go simultaneously
2. **Sequential**: Add panic recovery to main.go (depends on understanding interceptor setup)
3. **Sequential**: Build verification
4. **Sequential**: Run test suite
5. **Manual**: Verify crash scenarios (if possible in current environment)
