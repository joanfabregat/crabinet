import js from "@eslint/js";
import tsPlugin from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";

export default [
  {
    ignores: [
      "coverage/**",
      "dist/**",
      "node_modules/**",
      "playwright-report/**",
      "test-results/**",
    ],
  },
  js.configs.recommended,
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaFeatures: { jsx: true },
        ecmaVersion: "latest",
        sourceType: "module",
      },
    },
    plugins: {
      "@typescript-eslint": tsPlugin,
    },
    rules: {
      ...tsPlugin.configs.recommended.rules,
      "no-undef": "off",
    },
  },
  // Threat-model invariant 12: untrusted content renders as inert text, so
  // the application never reaches an HTML or script sink. Mirrored by
  // .semgrep/crabinet.yml; a new sink needs a threat-model update.
  {
    files: ["src/**/*.{ts,tsx}"],
    rules: {
      "no-eval": "error",
      "no-new-func": "error",
      "no-restricted-globals": [
        "error",
        { name: "open", message: "Popups are outside the preview contract." },
      ],
      "no-restricted-properties": [
        "error",
        {
          object: "document",
          property: "write",
          message: "Render untrusted content as inert text.",
        },
        {
          object: "document",
          property: "writeln",
          message: "Render untrusted content as inert text.",
        },
        {
          object: "window",
          property: "open",
          message: "Popups are outside the preview contract.",
        },
        {
          object: "globalThis",
          property: "open",
          message: "Popups are outside the preview contract.",
        },
      ],
      "no-restricted-syntax": [
        "error",
        {
          selector:
            "AssignmentExpression > MemberExpression.left[property.name=/^(innerHTML|outerHTML|srcdoc)$/]",
          message: "Render untrusted content as inert text, never as HTML.",
        },
        {
          selector: "CallExpression[callee.property.name='insertAdjacentHTML']",
          message: "Render untrusted content as inert text, never as HTML.",
        },
        {
          selector:
            "CallExpression[callee.property.name=/^(setAttribute|setAttributeNS)$/][arguments.length>=2] > Literal.arguments[value=/^srcdoc$/i]",
          message: "Previews never use srcdoc.",
        },
        {
          selector:
            "JSXAttribute[name.name=/^(dangerouslySetInnerHTML|srcdoc|srcDoc)$/]",
          message: "Render untrusted content as inert text, never as HTML.",
        },
        {
          selector: "Property[key.name='dangerouslySetInnerHTML']",
          message: "Render untrusted content as inert text, never as HTML.",
        },
        {
          selector: "NewExpression[callee.name='Function']",
          message: "Never compile strings into code.",
        },
        // no-implied-eval needs declared browser globals, which this config
        // leaves to TypeScript, so string timers are matched directly.
        {
          selector:
            "CallExpression[callee.name=/^(setTimeout|setInterval)$/][arguments.0.type=/^(Literal|TemplateLiteral|BinaryExpression)$/]",
          message: "Pass a function to timers, never a string of code.",
        },
        {
          selector:
            "CallExpression[callee.property.name=/^(setTimeout|setInterval)$/][arguments.0.type=/^(Literal|TemplateLiteral|BinaryExpression)$/]",
          message: "Pass a function to timers, never a string of code.",
        },
      ],
    },
  },
];
