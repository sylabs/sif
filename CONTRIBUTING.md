# Contributor's Agreement

You are under no obligation whatsoever to provide any bug fixes, patches,
or upgrades to the features, functionality or performance of the source
code ("Enhancements") to anyone; however, if you choose to make your
Enhancements available either publicly, or directly to the project,
without imposing a separate written license agreement for such
Enhancements, then you hereby grant the following license: a non-exclusive,
royalty-free perpetual license to install, use, modify, prepare derivative
works, incorporate into other computer software, distribute, and sublicense
such enhancements or derivative works thereof, in binary and source code
form.

## Contributing

When contributing to SIF, it is important to properly communicate the
gist of the contribution. If it is a simple code or editorial fix, simply
explaining this within the GitHub Pull Request (PR) will suffice. But if this
is a larger fix or Enhancement, you are advised to first discuss the change
with the project leader or developers.

Please note we have a code of conduct, described below. Please follow it in
all your interactions with the project members and users.

### Pull Requests (PRs)

#### Process

1. Essential bug fix PRs should be sent to both `main` and release branches (if applicable).
1. Small bug fix and feature enhancement PRs should be sent to `main` only.
1. Follow the existing code style precedent. Use [golangci-lint](https://golangci-lint.run) to ensure your code is properly formatted and free of lint.
1. For any new functionality, please write appropriate tests that will run as part of the continuous integration system ([CircleCI](https://circleci.com/gh/sylabs/workflows/sif)).
1. Ensure the project's default copyright and header have been included in any new source files.
1. Make sure you have run `go test ./...` and all tests succeed before submitting the PR.
1. Is the code human understandable? This can be accomplished via a clear code style as well as documentation and/or comments.
1. The pull request will be reviewed by others, and finally merged when all requirements are met.
1. Documentation must be provided if necessary (next section)

#### Documentation

1. If you are changing any of the following:

   - renamed commands
   - deprecated / removed commands
   - changed defaults
   - backward incompatible changes (recipe file format? image file format?)
   - migration guidance (how to convert images?)
   - changed behaviour (recipe sections work differently)

## Code of Conduct

### Our Pledge

In the interest of fostering an open and welcoming environment, we as
contributors and maintainers pledge to making participation in our project and
our community a harassment-free experience for everyone, regardless of age, body
size, disability, ethnicity, gender identity and expression, level of experience,
nationality, personal appearance, race, religion, or sexual identity and
orientation.

### Our Standards

Examples of behavior that contributes to creating a positive environment
include:

- Using welcoming and inclusive language
- Being respectful of differing viewpoints and experiences
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

Examples of unacceptable behavior by participants include:

- The use of sexualized language or imagery and unwelcome sexual attention or
  advances
- Trolling, insulting/derogatory comments, and personal or political attacks
- Public or private harassment
- Publishing others' private information, such as a physical or electronic
  address, without explicit permission
- Other conduct which could reasonably be considered inappropriate in a
  professional setting

#### Our Responsibilities

Project maintainers are responsible for clarifying the standards of acceptable
behavior and are expected to take appropriate and fair corrective action in
response to any instances of unacceptable behavior.

Project maintainers have the right and responsibility to remove, edit, or
reject comments, commits, code, wiki edits, issues, and other contributions
that are not aligned to this Code of Conduct, or to ban temporarily or
permanently any contributor for other behaviors that they deem inappropriate,
threatening, offensive, or harmful.

### Scope

This Code of Conduct applies both within project spaces and in public spaces
when an individual is representing the project or its community. Examples of
representing a project or community include using an official project e-mail
address, posting via an official social media account, or acting as an appointed
representative at an online or offline event. Representation of a project may be
further defined and clarified by project maintainers.

### Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be
reported by contacting the project leaders ([info@sylabs.io]). All
complaints will be reviewed and investigated and will result in a response
that is deemed necessary and appropriate to the circumstances. The project
team is obligated to maintain confidentiality with regard to the reporter of
an incident. Further details of specific enforcement policies may be posted
separately.

Project maintainers, contributors and users who do not follow or enforce the
Code of Conduct in good faith may face temporary or permanent repercussions
with their involvement in the project as determined by the project's leader(s).

### Attribution

This Code of Conduct is adapted from the [Contributor Covenant][homepage], version 1.4,
available at [http://contributor-covenant.org/version/1/4][version]

[homepage]: http://contributor-covenant.org
[version]: http://contributor-covenant.org/version/1/4/
