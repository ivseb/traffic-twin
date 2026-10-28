using Xunit;

// The tests share process-wide state (the HttpClient diagnostics listener, TrafficTwinAgent.Current): run them one at a time.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
