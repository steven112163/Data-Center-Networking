#!/bin/bash

SESSION="DCNProject3"

tmux start-server

if [ "$(tmux ls | grep ${SESSION})" ]; then
  tmux kill-session -t ${SESSION}
fi

tmux new-session -d -s ${SESSION} -n dcn_project
tmux set remain-on-exit on
tmux split-window -h

tmux send-keys -t 1 "sudo mn --topo mytopo --custom topo.py --controller remote,ip=127.0.0.1" Enter
tmux send-keys -t 2 "ryu-manager controller.py" Enter

tmux -2 attach-session -t ${SESSION}