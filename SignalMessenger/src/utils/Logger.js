/**
 * Logger.js
 * Simple logging utility
 */

class Logger {
  info(context, message) {
    console.log(`[${context}] INFO: ${message}`);
  }
  
  warn(context, message) {
    console.warn(`[${context}] WARN: ${message}`);
  }
  
  error(context, message) {
    console.error(`[${context}] ERROR: ${message}`);
  }
  
  debug(context, message) {
    if (__DEV__) {
      console.debug(`[${context}] DEBUG: ${message}`);
    }
  }
}

export default new Logger();
