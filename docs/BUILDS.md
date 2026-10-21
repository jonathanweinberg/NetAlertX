# NetAlertX Builds: Choose Your Path

NetAlertX provides different installation methods for different needs. This guide helps you choose the right path for security, experimentation, or development.

## 1. Hardened Appliance (Default Production)

> [!NOTE]
> Use this image if: You want to use NetAlertX securely.

### Who is this for?

All users who want a stable, secure, "set-it-and-forget-it" appliance.

### Methodology

- Multi-stage Alpine build
- Aggressively "amputated"
- Locked down for max security

### Source

`Dockerfile (hardened target)`

## 2. "Tinkerer's" Image (Insecure VM-Style)

> [!NOTE]
> Use this image if: You want to experiment with NetAlertX.

### Who is this for?

Power users, developers, and "tinkerers" wanting a familiar "VM-like" experience.

### Methodology

- Traditional Debian build
- Includes full un-hardened OS
- Contains `apt`, `sudo`, `git`

### Source

`Dockerfile.debian`

## 3. Contributor's Devcontainer (Project Developers)

> [!NOTE]
> Use this image if: You want to develop NetAlertX itself.

### Who is this for?

Project contributors who are actively writing and debugging code for NetAlertX.

### Methodology


- Builds `FROM runner` stage
- Loaded by VS Code
- Full debug tools: `xdebug`, `pytest`


### Source

`Dockerfile (devcontainer target)`

# Visualizing the Trade-Offs

This chart compares the three builds across key attributes. A higher score means "more of" that attribute. Notice the clear trade-offs between security and development features.

![tradeoffs](./img/BUILDS/build_images_options_tradeoffs.png)


# Build Process & Origins

The final images originate from two different files and build paths. The main `Dockerfile` uses stages to create *both* the hardened and development container images.

## Official Build Path

Dockerfile -> builder (Stage 1) -> runner (Stage 2) ->  hardened (Final Stage) (Production Image) + devcontainer (Final Stage) (Developer Image)


## Legacy Build Path

Dockerfile.debian -> "Tinkerer's" Image (Insecure VM-Style Image)

## PHP Security Floor

Container builds verify the CLI and each installed PHP serving binary before
hardening. The guard also checks the curl, session and sqlite3 extensions.
PHP 8.3 packages must be at least 8.3.36, which fixes CVE-2026-109618 and
CVE-2026-109619. The guard has equivalent upstream security floors for reviewed
PHP 8.2, 8.4 and 8.5 releases, but this does not change the builds from PHP 8.3.

If Alpine has not published the required packages for a target architecture,
the build intentionally fails rather than producing another affected image.
Do not mix repositories from other Alpine branches, bypass package signatures,
or lower the version floor to make the build pass. Rebuild after the maintained
repositories provide the patched PHP package family. A vendor backport with an
older upstream version requires separate verification and an explicit policy
change; the numeric guard does not infer backport safety.

The same checks run in the Debian build against its configured package source.
An application release tag alone does not establish the bundled PHP version.

Run the focused guard tests with:

```bash
python3 -m unittest discover -s test/build -p 'test_php_runtime.py'
```

These focused checks do not replace the full contributor test suite or the
production build matrix for amd64, arm64, arm/v7 and arm/v6.
