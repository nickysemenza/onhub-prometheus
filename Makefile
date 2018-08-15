IMAGE=nicky/onhub-prometheus
all: dev

dev:
	go run main.go data.go
docker-build:
	docker build -t $(IMAGE) .
docker-run:
	docker run -p 9200:9200 -e "ONHUB_HOST=10.0.0.1" $(IMAGE) 
docker-dev: docker-build docker-run

docker-push:
	docker push $(IMAGE):latest