.PHONY: agent-upgrade
agent-upgrade:
	go build -o ./nezha-agent && mv /opt/nezha/agent/nezha-agent /opt/nezha/agent/nezha-agent.old && cp ./nezha-agent /opt/nezha/agent/nezha-agent && systemctl restart nezha-agent.service
