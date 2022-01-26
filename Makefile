NAME   := k8s-secret-editor
TAG    := $$(git rev-parse --short HEAD)
IMG    := ${NAME}:${TAG}
LATEST := ${NAME}:latest
DOCKER_IO_IMG := docker.io/$(DOCKER_USER)/${LATEST}

.PHONY: build push login

all: build login push

build:
	@docker build -t ${IMG} .
	@docker tag ${IMG} ${LATEST}
	@docker tag ${IMG} ${DOCKER_IO_IMG}


push:
	@docker push ${DOCKER_IO_IMG}

login:
	@docker login -u $(DOCKER_USER) -p $(DOCKER_PWD)
