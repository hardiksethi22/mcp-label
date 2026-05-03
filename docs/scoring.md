# Scoring

`mcp-label` uses a transparent, documented scoring model.

## Base Score

Each server starts at **100 points**.

## Deductions

### Permission Findings

| Level    | Deduction |
|----------|-----------|
| Info     | 0         |
| Low      | -5        |
| Medium   | -12       |
| High     | -25       |
| Critical | -40       |

### Install Risks

| Risk                 | Deduction |
|----------------------|-----------|
| Unpinned package     | -10       |
| Unpinned Docker      | -10       |
| Docker privileged    | -30       |
| Docker host network  | -15       |
| Docker broad mount   | -25       |
| Curl pipe shell      | -40       |
| Local script         | -10       |

### Compound Deductions

| Condition                         | Extra Deduction |
|-----------------------------------|-----------------|
| Secret + likely write access      | -15             |
| Shell execution                   | -20             |

## Grade Mapping

| Grade | Score Range |
|-------|-------------|
| A     | 90–100      |
| B     | 75–89       |
| C     | 60–74       |
| D     | 40–59       |
| F     | Below 40    |

## Risk Mapping

| Risk     | Criteria                                          |
|----------|---------------------------------------------------|
| Low      | No high or critical findings and score ≥ 85       |
| Medium   | Score ≥ 70 and no critical findings               |
| High     | Score ≥ 40 or any high finding                    |
| Critical | Any critical finding or score < 40                |

## Customization

Scoring is intentionally transparent. Teams can adapt deductions and thresholds by forking or extending the scoring module.

