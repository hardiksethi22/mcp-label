# Permission Ontology

`mcp-label` uses a versioned permission ontology to categorize findings.

## Version 0.1

| Permission ID         | Description                              |
|-----------------------|------------------------------------------|
| `filesystem.read`     | Read files from the local filesystem     |
| `filesystem.write`    | Write or create files                    |
| `filesystem.delete`   | Delete files                             |
| `shell.execute`       | Execute shell commands                   |
| `network.fetch`       | Make outbound network requests           |
| `network.listen`      | Listen for incoming connections           |
| `browser.control`     | Control a browser instance               |
| `browser.read_session`| Read browser session data                |
| `repo.read`           | Read repository data                     |
| `repo.write`          | Write to repositories                    |
| `repo.admin`          | Administrative repository access         |
| `database.query`      | Query a database                         |
| `database.mutate`     | Modify database data                     |
| `cloud.read`          | Read cloud resources                     |
| `cloud.write`         | Modify cloud resources                   |
| `cloud.admin`         | Administrative cloud access              |
| `email.read`          | Read email messages                      |
| `email.send`          | Send email messages                      |
| `calendar.read`       | Read calendar events                     |
| `calendar.write`      | Modify calendar events                   |
| `secrets.env`         | Receives secrets via environment          |
| `secrets.files`       | Accesses secret files                    |
| `payments.read`       | Access payment data                      |
| `payments.charge`     | Initiate financial transactions          |
| `unknown`             | Unclassified permission                  |

## Finding Structure

Every finding maps to one or more permission IDs and includes:

- **id**: Unique finding identifier
- **permission**: Permission ID from the ontology
- **level**: Severity (info, low, medium, high, critical)
- **confidence**: How confident the heuristic is (low, medium, high)
- **evidence**: What triggered the finding
- **explanation**: What it means
- **recommendation**: What to do about it (optional)

