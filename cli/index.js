#!/usr/bin/env node
import { main } from "../dist/run-cli.js";

const code = await main(process.argv.slice(2));
process.exit(code);
