# Wyatt Agent Examples & Roadmap

This directory (`agents/`) contains the implementations of the AI agents that connect to the Wyatt Daemon. 

Each agent represents a different architecture and level of complexity, progressively demonstrating how Wyatt operates at scale.

---

## 1. `simple_agent.py`
**The Proof of Concept**
* **Complexity**: Very Low (Single script)
* **What it does**: Sends a hardcoded JSON string over the socket to test if the Wyatt Daemon is alive and enforcing exactly 1 rule. 
* **Purpose**: Developer testing and sanity checking.

---

## 2. `adversarial_agent.py` (DevOps Stress Tester)
**The Enforcement Verifier**
* **Complexity**: Medium (Class-based, deterministic)
* **What it does**: A structured Python script that runs 6 distinct phases of "attacks" (17 tasks total), imitating a rogue or hallucinating agent. 
* **Purpose**: This guarantees that Wyatt correctly intercepts edge cases like path traversal (`../../`), null bytes (`\x00`), unauthorized tools via OPA, and redacts secrets from context. It does *not* use a real LLM—it deterministically fires the exact JSON payloads an LLM *would* produce to guarantee 100% test coverage.

---

## 3. The LangChain Agent (DeepSeek)
**The Dynamic Real-World Agent** *(Upcoming Roadmap)*
* **Complexity**: High (Modular framework)
* **Architecture**: Real-world but simplistic. It will use LangChain's `create_react_agent` powered by a DeepSeek LLM. 
* **Modularity**: It will not be a monolithic script. The project will be modularized into:
  - `agents/langchain_agent/tools/` (Translating Wyatt socket calls to LangChain `@tool`)
  - `agents/langchain_agent/prompts/` (System instructions)
  - `agents/langchain_agent/main.py` (The ReAct loop)
* **Purpose**: Proves Wyatt works flawlessly with industry-standard frameworks. The prompt will say *"Figure out what's running on this server,"* and the LLM will dynamically decide to read files, which Wyatt will intercept in real-time.

---

## 4. The LangGraph Agent (Enterprise Swarm)
**The Production-Grade State Machine** *(Upcoming Roadmap)*
* **Complexity**: Very High (Multi-Node Swarm)
* **Architecture**: A large-scale agentic system using LangGraph. We will separate execution into distinct Graph Nodes. 
* **Modularity**: 
  - `agents/langgraph_swarm/state.py` (TypedDict state tracking)
  - `agents/langgraph_swarm/nodes/planner.py` (Analyzes and dictates actions)
  - `agents/langgraph_swarm/nodes/worker.py` (Executes tools through Wyatt)
  - `agents/langgraph_swarm/nodes/reviewer.py` (Reviews Wyatt's redacted output)
* **Purpose**: Proves Wyatt's viability in asynchronous, distributed swarms where agents pass state to each other.

---

## 5. "OpenClaw-Lite" (LangGraph + Temporal)
**The Distributed Enterprise Daemon** *(Upcoming Roadmap)*
* **Complexity**: Extreme (Massive System)
* **Architecture**: A mix of LangGraph (for cognitive state) and Temporal (for backend durable execution). This will be a fully distributed AI agent mirroring a massive architecture like *OpenClaw*.
* **Modularity**: Services-oriented architecture containing its own workers, database backends, API gateways, and cognitive engines.
* **Purpose**: The ultimate test of Wyatt. Demonstrates how the Wyatt Daemon securely acts as the execution firewall for a highly complex, multi-server enterprise AI product. 
