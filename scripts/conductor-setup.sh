#!/usr/bin/env bash

go mod download &
npm ci &

wait
