import asyncio
from adk.agents import LlmAgent
from adk.tools import McpToolset, StdioServerParameters

async def main():
    # 1. Define how to launch your local custom MCP server
    server_params = StdioServerParameters(
        command="python3",
        args=["network_audit_server.py"]
    )
    
    # 2. Package it inside ADK's McpToolset wrapper
    mcp_toolset = McpToolset(servers=[server_params])
    
    # 3. Create the ADK agent and attach the toolset
    agent = LlmAgent(
        name="NetWorkAuditAgent",
        instructions="You are a helpful network security analyst  for small enteriprise. Use scan network , audit network ,udp anomalies,os fingerprinting, firewall id evasion tool to answer questions.",
        tools=[mcp_toolset]
    )
    
    # 4. Prompt the agent
    response = await agent.chat("Please investigate the subnet for 172.17.0.1/24 range")
    print("Agent Response:\n", response)
    
if __name__ == "__main__":
    asyncio.run(main())