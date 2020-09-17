## this file is sourced, so no need to even monkey with its permissions or shebang
nohup $MAVEN_CONFIG/.venv/bin/moto_server --host 0.0.0.0 --port 4615 &
echo "pausing for moto to warm up ..." >&2
sleep 2
echo "RUN TESTS NOW" >&2
## and here you could do org creation, population, sample data, that kind of thing
