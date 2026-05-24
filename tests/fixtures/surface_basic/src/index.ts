import express from "express";
import { WebSocketServer } from "ws";

const app = express();
const port = process.env.PORT;

app.post("/submit", (_req, res) => res.send("ok"));
new WebSocketServer({ port: 8080 });

export { app, port };
