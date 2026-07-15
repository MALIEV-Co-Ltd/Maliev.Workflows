using Maliev.Workflows.Smoke;
using Xunit;

namespace Maliev.Workflows.Smoke.Tests;

public sealed class HealthScoreTests
{
    [Theory]
    [InlineData(-1, 0)]
    [InlineData(50, 50)]
    [InlineData(101, 100)]
    public void Clamp_returns_a_bounded_score(int score, int expected)
    {
        Assert.Equal(expected, HealthScore.Clamp(score));
    }
}
