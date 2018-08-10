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