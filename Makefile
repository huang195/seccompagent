GO := go
GO_BUILD := go build

IMAGE_TAG=$(shell ./tools/image-tag)
IMAGE_BRANCH_TAG=$(shell ./tools/image-tag branch)
CONTAINER_REPO ?= haih/spireseccompagent

.PHONY: seccompagent
seccompagent:
	$(GO_BUILD) -o seccompagent ./cmd/seccompagent

.PHONY: container-build
container-build:
	docker build -t $(CONTAINER_REPO):$(IMAGE_TAG) -f Dockerfile .
	docker tag $(CONTAINER_REPO):$(IMAGE_TAG) $(CONTAINER_REPO):$(IMAGE_BRANCH_TAG)

.PHONY: container-push
container-push:
	docker push $(CONTAINER_REPO):$(IMAGE_TAG)
	docker push $(CONTAINER_REPO):$(IMAGE_BRANCH_TAG)

.PHONY: vendor
vendor:
	$(GO) mod tidy
	$(GO) mod vendor
	$(GO) mod verify

.PHONY: test
test:
	go test -test.v ./...

.PHONY: falco-plugin
falco-plugin:
	DOCKER_BUILDKIT=1 docker build -f falco-plugin/Dockerfile --output=falco-plugin/ .
