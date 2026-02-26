/**
 * Signal Messenger - Entry Point
 * Production-grade secure messaging app with end-to-end encryption
 */
import { AppRegistry } from "react-native";
import App from "./App";
import { name as appName } from "./app.json";

AppRegistry.registerComponent(appName, () => App);
