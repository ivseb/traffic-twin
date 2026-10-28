using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using TrafficTwin.Sdk.Sanitizing;
using Xunit;

namespace TrafficTwin.Sdk.Tests;

/// <summary>Runs every conformance vector (conformance/vectors/*.json) and compares byte for byte.</summary>
public class VectorTests
{
    public static IEnumerable<object[]> Vectors() =>
        Directory.GetFiles(Path.Combine(Paths.Conformance(), "vectors"), "*.json").OrderBy(f => f, StringComparer.Ordinal)
            .Select(f => new object[] { Path.GetFileNameWithoutExtension(f) });

    [Theory]
    [MemberData(nameof(Vectors))]
    public void Vector(string id)
    {
        string root = Paths.Conformance();
        var vec = VectorRunner.Parse(File.ReadAllBytes(Path.Combine(root, "vectors", id + ".json")));
        var expected = (Dictionary<string, object?>)vec["expected"]!;
        var got = VectorRunner.Run(vec, root);
        string outcome = (string)expected["outcome"]!;
        Assert.True(outcome == got.Outcome, $"{id}: outcome expected {outcome}, got {got.Outcome} ({got.Code})");
        switch (outcome)
        {
            case "event":
                Assert.True((string)expected["canonical"]! == got.Canonical, $"{id}:\nexpected {expected["canonical"]}\n     got {got.Canonical}");
                break;
            case "not_sampled":
                Assert.Equal((string)expected["sampled_by"]!, got.SampledBy);
                break;
            case "refused":
                Assert.True((string)expected["code"]! == got.Code, $"{id}: refused code expected {expected["code"]}, got {got.Code}");
                break;
        }
    }

    [Fact]
    public void AllVectorsAreCovered()
    {
        Assert.True(Vectors().Count() >= 400, "unexpectedly few vectors");
    }
}
