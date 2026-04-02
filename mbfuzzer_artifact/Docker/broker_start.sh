#!/bin/bash

# Define the list of brokers
brokers=("mosquitto" "nanomq" "flashmq" "emqx" "vernemq" "hivemq")

# Declare an associative array to hold container names and their IDs
declare -A container_ids

# Get the list of running containers and filter by names
for broker in "${brokers[@]}"; do
    # Find the container ID for the broker
    container_id=$(docker ps --filter "name=$broker" --format "{{.ID}}")
    if [ -n "$container_id" ]; then
        container_ids[$broker]=$container_id
        echo "Found $broker container with ID: $container_id"
    else
        echo "WARNING: $broker container not found."
    fi
done

# Execute the command in each broker's container
for broker in "${brokers[@]}"; do
    container_id=${container_ids[$broker]}
    if [ -n "$container_id" ]; then
        docker exec -d "$container_id" /root/run.sh "$broker"
        echo "Executed /root/run.sh $broker in container $container_id"
    else
        echo "WARNING: Skipped executing command for $broker as container ID not found."
    fi
done