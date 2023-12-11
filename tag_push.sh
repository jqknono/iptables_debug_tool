docker build -t simple_echo_server:latest .
docker tag simple_echo_server:latest docker.io/jqknono/simple_echo_server:latest
docker push docker.io/jqknono/simple_echo_server:latest