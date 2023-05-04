# This bash script contains shared logic that is used to parse
# command line arguments. It is meant to be sourced from within the
# build scripts.
# This script parses command line arguments and exposes variables such
# as $PROFILE, and $FEATURES.
#
# Variables:
#
# $PROFILE: Can contain "--release" or "". By default it is set to
#           "--release".
# $FEATURES: Contains a value of a feature passed by "--feature foo",
#            as "--feature foo". In case of no --feature switch is
#            found in $@ then empty string is used.
#
# Example:
#
# $ source ./build_common.sh --release --feature foo
# $ echo $FEATURES
# --features foo
# $ echo $PROFILE
# --release

# Builds release profile unless specified other
PROFILE="--release"
# Features switch that will be passed to cargo in a docker container
FEATURES=""

# Parse arguemnmts
while [[ $# -gt 0 ]]
do
    key="$1"
    case $key in
        --debug)
        # Without this argument cargo builds dev binary by default
        PROFILE=""
        shift
        ;;
        --release)
        PROFILE="--release"
        shift
        ;;
        --features)
        FEATURES="$2"
        shift
        shift
        ;;
        *)
        shift
        ;;
    esac
done

# Prepare `--features $FOO` only if --features is passed to this script.
if [ "$FEATURES" != '' ]; then
    # Add --features with the input provided
    FEATURES="--features $FEATURES"
fi