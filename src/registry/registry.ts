import bodyParser from "body-parser";
import express from "express";
import {REGISTRY_PORT} from "../config";

export type Node = {
  nodeId: number;
  pubKey: string
};


export type GetNodeRegistryBody = {
  nodes: Node[];
};

const nodeRegistry: GetNodeRegistryBody = {
  nodes: [],
};

export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());

  _registry.get("/status", (_, res) => {
    res.status(200).send("live");
  });

  // Register a node: if the node is not already registered, add it to the registry
  _registry.post("/registerNode", async (req, res) => {
    try {
      const {nodeId, pubKey} = req.body;
      if (!nodeRegistry.nodes.find((n) => n.nodeId === nodeId))
        nodeRegistry.nodes.push({nodeId, pubKey});
      res.status(200).send("Node registered successfully");
    } catch (error) {
      res.status(500).send("Internal server error");
    }
  });


  _registry.get("/getNodeRegistry", (_, res) => {
    try {
      res.status(200).send(nodeRegistry);
    } catch (error) {
      res.status(500).send("Internal server error");
    }
  });

  return _registry.listen(REGISTRY_PORT, () => {
    console.log(`registry is listening on port ${REGISTRY_PORT}`);
  });
}