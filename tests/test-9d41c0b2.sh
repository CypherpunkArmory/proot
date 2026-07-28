if [ -z "$(which timeout)" ] || [ -z "$(which yes)" ] || [ -z "$(which head)" ]; then
    exit 125;
fi

# Regression test: a reader that closes the pipe early must not deadlock
# the writer.  proot shadows pipe read ends so racing writers do not get
# EPIPE (see test-b3e7f2d8.sh), but a shadow that is never released
# hands the writer a reader that never reads: once the pipe fills, the
# writer blocks in write() instead of dying from EPIPE, and whoever
# waits on it waits forever.  This is how mandb used to hang on manual
# pages whose decompressed output exceeds the pipe buffer.

timeout 10 ${PROOT} sh -c 'yes | head -1' > /dev/null
