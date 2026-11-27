#!/bin/bash
# Creates the 5 starter detection rules in ./rules
mkdir -p rules
cat > rules/brute_force.yml << 'EOF'
title: Many failed logons from one source
id: lab-001
status: test
description: Password guessing from a single IP
tags: [attack.credential_access, attack.t1110]
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4625
  condition: selection | count() by SourceIP >= 5
level: high
EOF
cat > rules/encoded_powershell.yml << 'EOF'
title: Hidden or encoded PowerShell
id: lab-002
status: test
description: PowerShell launched with encoded or hidden-window options
tags: [attack.execution, attack.t1059.001]
logsource: {product: windows, category: process_creation}
detection:
  selection:
    EventID: 4688
    CommandLine|contains:
      - '-enc'
      - '-w hidden'
  condition: selection
level: high
EOF
cat > rules/new_admin.yml << 'EOF'
title: User added to Administrators group
id: lab-003
status: test
tags: [attack.persistence, attack.t1098]
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 4732
    Group: Administrators
  condition: selection
level: critical
EOF
cat > rules/log_cleared.yml << 'EOF'
title: Security audit log cleared
id: lab-004
status: test
tags: [attack.defense_evasion, attack.t1070.001]
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 1102
  condition: selection
level: critical
EOF
cat > rules/whoami.yml << 'EOF'
title: whoami executed
id: lab-005
status: test
tags: [attack.discovery, attack.t1033]
logsource: {product: windows, category: process_creation}
detection:
  selection:
    EventID: 4688
    CommandLine|startswith: 'whoami'
  condition: selection
level: low
EOF
echo "Created $(ls rules | wc -l) rules in ./rules"

