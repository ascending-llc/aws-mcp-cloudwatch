# Documentation Organization Plan

## Files Created Today

### Category 1: Operational Files (KEEP IN PLACE)
These are used directly by the system and should stay near their associated files.

```
.github/workflows/
├── ci-cloudwatch.yml          ✅ KEEP - Active workflow
└── deploy-cloudwatch.yml      ✅ KEEP - Active workflow

k8s/jarvis-demo/
├── values.yaml                ✅ KEEP - Helm values for deployment
├── deployment.yaml            ✅ KEEP - Primary k8s manifest
└── deployment-no-auth.yaml    ✅ KEEP - Testing k8s manifest

src/cloudwatch-mcp-server/
├── middleware.py              ✅ KEEP - Code file
└── CLAUDE.md                  ✅ KEEP - Developer guide (frequently accessed)
```

### Category 2: Reference Documentation (MOVE TO DOCS)
These are guides, reviews, and reference material.

```
CURRENT LOCATIONS → PROPOSED LOCATIONS

Root Level:
├── CICD_IMPLEMENTATION_SUMMARY.md       → docs/cicd/IMPLEMENTATION_SUMMARY.md
└── DEPLOYMENT_OPTIONS.md                → docs/deployment/OPTIONS.md

src/cloudwatch-mcp-server/:
├── IAM_IDENTITY_CENTER_SETUP.md         → docs/authentication/IAM_IDENTITY_CENTER_SETUP.md
├── AWS_AUTH_GUIDE.md                    → docs/authentication/AWS_AUTH_GUIDE.md
├── STARLETTE_AUTH_GUIDE.md              → docs/authentication/STARLETTE_AUTH_GUIDE.md
├── AUTHENTICATION_CHANGES_REVIEW.md     → docs/authentication/IMPLEMENTATION_REVIEW.md
├── DEPLOYMENT_EKS.md                    → docs/deployment/EKS_DEPLOYMENT_GUIDE.md
└── DEPLOYMENT.md                        → docs/deployment/DOCKER_DEPLOYMENT_GUIDE.md

k8s/jarvis-demo/:
├── README.md                            → docs/kubernetes/OPERATIONS_GUIDE.md
├── DEPLOYMENT_NO_AUTH.md                → docs/kubernetes/NO_AUTH_SETUP.md (or keep in k8s/)
└── TESTING_SETUP.md                     → docs/kubernetes/TESTING_SETUP.md (or keep in k8s/)
```

## Proposed Final Structure

```
aws-mcp-cloudwatch/
│
├── .github/
│   └── workflows/
│       ├── ci-cloudwatch.yml            # Active workflow
│       └── deploy-cloudwatch.yml        # Active workflow
│
├── k8s/
│   └── jarvis-demo/
│       ├── values.yaml                  # Helm values
│       ├── deployment.yaml              # Production manifest
│       ├── deployment-no-auth.yaml      # Testing manifest
│       ├── README.md                    # Quick reference (optional: keep or move)
│       ├── DEPLOYMENT_NO_AUTH.md        # Testing guide (optional: keep or move)
│       └── TESTING_SETUP.md             # Testing guide (optional: keep or move)
│
├── src/
│   └── cloudwatch-mcp-server/
│       ├── cloudwatch_mcp_server/
│       │   ├── middleware.py            # Code
│       │   └── ...
│       ├── CLAUDE.md                    # Developer quick reference
│       └── README.md                    # Main project README
│
└── docs/                                # NEW: Consolidated documentation
    ├── README.md                        # Documentation index
    ├── authentication/
    │   ├── README.md                    # Auth overview
    │   ├── IAM_IDENTITY_CENTER_SETUP.md
    │   ├── AWS_AUTH_GUIDE.md
    │   ├── STARLETTE_AUTH_GUIDE.md
    │   └── IMPLEMENTATION_REVIEW.md
    ├── deployment/
    │   ├── README.md                    # Deployment overview
    │   ├── OPTIONS.md                   # Choose deployment method
    │   ├── EKS_DEPLOYMENT_GUIDE.md
    │   └── DOCKER_DEPLOYMENT_GUIDE.md
    ├── cicd/
    │   ├── README.md                    # CI/CD overview
    │   └── IMPLEMENTATION_SUMMARY.md
    └── kubernetes/
        ├── README.md                    # Kubernetes overview
        ├── OPERATIONS_GUIDE.md
        ├── NO_AUTH_SETUP.md             # Alternative: keep in k8s/jarvis-demo/
        └── TESTING_SETUP.md             # Alternative: keep in k8s/jarvis-demo/
```

## Decision Points

### Option A: Move All Reference Docs to `docs/`
**Pros:**
- Clean separation of operational vs reference
- All guides in one place
- Easier to maintain documentation
- Clear "docs" location for users

**Cons:**
- K8s guides separated from manifests
- More directory jumping when deploying

**Structure:**
```
k8s/jarvis-demo/
├── values.yaml
├── deployment.yaml
└── deployment-no-auth.yaml

docs/kubernetes/
├── OPERATIONS_GUIDE.md
├── NO_AUTH_SETUP.md
└── TESTING_SETUP.md
```

### Option B: Keep K8s Docs with Manifests, Move Others
**Pros:**
- Deployment guides stay with manifests
- Easy to reference while deploying
- Less reorganization

**Cons:**
- Documentation split across locations
- Less clear "docs" location

**Structure:**
```
k8s/jarvis-demo/
├── values.yaml
├── deployment.yaml
├── deployment-no-auth.yaml
├── README.md
├── DEPLOYMENT_NO_AUTH.md
└── TESTING_SETUP.md

docs/
├── authentication/...
├── deployment/...
└── cicd/...
```

### Option C: Minimal Move (Recommended)
**Keep operational docs near their files, move only overview/review docs**

**Move to docs:**
- CICD_IMPLEMENTATION_SUMMARY.md (overview/summary)
- AUTHENTICATION_CHANGES_REVIEW.md (review/summary)
- AWS_AUTH_GUIDE.md (general reference)
- STARLETTE_AUTH_GUIDE.md (general reference)

**Keep in place:**
- k8s/jarvis-demo/*.md (deployment guides stay with manifests)
- src/cloudwatch-mcp-server/DEPLOYMENT_EKS.md (deployment guide stays with code)
- src/cloudwatch-mcp-server/IAM_IDENTITY_CENTER_SETUP.md (setup guide stays with code)
- src/cloudwatch-mcp-server/DEPLOYMENT.md (existing, stays)
- src/cloudwatch-mcp-server/CLAUDE.md (developer guide, stays)
- DEPLOYMENT_OPTIONS.md (decision guide, keep at root or move)

**Structure:**
```
aws-mcp-cloudwatch/
├── DEPLOYMENT_OPTIONS.md           # Quick decision guide at root
├── k8s/jarvis-demo/
│   ├── *.yaml                      # Manifests
│   ├── README.md                   # K8s operations
│   ├── DEPLOYMENT_NO_AUTH.md       # No-auth setup
│   └── TESTING_SETUP.md            # Testing setup
├── src/cloudwatch-mcp-server/
│   ├── CLAUDE.md                   # Developer guide
│   ├── DEPLOYMENT.md               # Docker deployment
│   ├── DEPLOYMENT_EKS.md           # EKS deployment
│   └── IAM_IDENTITY_CENTER_SETUP.md # Auth setup
└── docs/
    ├── README.md                   # Index to all docs
    ├── authentication/
    │   ├── AWS_AUTH_GUIDE.md       # General auth reference
    │   ├── STARLETTE_AUTH_GUIDE.md # Middleware reference
    │   └── IMPLEMENTATION_REVIEW.md # Review doc
    └── cicd/
        └── IMPLEMENTATION_SUMMARY.md # CI/CD summary
```

## Recommendation

**Use Option C (Minimal Move):**

1. Keep deployment/setup guides near their operational files
2. Move only overview/reference/review documents to `docs/`
3. Create `docs/README.md` as an index pointing to all documentation

This way:
- ✅ Deployment guides stay with manifests (easy access)
- ✅ Setup guides stay with code (easy access)
- ✅ Reference material consolidated in `docs/`
- ✅ Clear organization without over-structuring

## Next Steps

1. Choose option (A, B, or C)
2. Create `docs/` structure
3. Move selected files
4. Create `docs/README.md` index
5. Update references in moved files
6. Test that all paths still work
