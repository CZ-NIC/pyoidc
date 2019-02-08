IMAGENAME?=oidctest-local-it
CONTAINERNAME?=oidctest-it

.PHONY: help
help:
	@echo "Usage"
	@echo "  build  : Build the image"
	@echo "  delete : Deletes the container"
	@echo "  logs   : Shows container logs"
	@echo "  shell  : Starts interactive shell"
	@echo "  start  : Starts the container (you need to run 'make build' once first)"
	@echo "  status : Shows container status"
	@echo "  stop   : Stops the container"
	@echo "  "
	@echo "Other oidctest containers must be already running when you start this container"

.PHONY: build
build:
	docker build -t "$(IMAGENAME)" .
	docker run --net=host --name "$(CONTAINERNAME)" -d "$(IMAGENAME)"


.PHONY: start
start:
	docker container start "$(CONTAINERNAME)"
	docker container logs --follow "$(CONTAINERNAME)"

.PHONY: stop
stop:
	docker stop "$(CONTAINERNAME)"

.PHONY: delete
delete:
	docker rm "$(CONTAINERNAME)"

.PHONY: logs
logs:
	docker container logs --follow "$(CONTAINERNAME)"

.PHONY: shell
shell:
	docker exec -it "$(CONTAINERNAME)" bash

.PHONY: status
status:
	docker ps -f name="$(CONTAINERNAME)"
