import "@testing-library/jest-dom/vitest";
import { render, screen } from "@testing-library/preact";
import { describe, expect, it } from "vitest";

import { App } from "./app";

describe("App", () => {
  it("identifies the application", () => {
    render(<App />);
    expect(screen.getByRole("heading", { name: "Index" })).toBeInTheDocument();
  });
});
