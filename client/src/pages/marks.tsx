import { useEffect, useRef } from "react";
import * as d3 from "d3";

export default function MarksPage() {
  const d3Container = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (d3Container.current) {
      // Remove any previous SVG
      d3.select(d3Container.current).selectAll("svg").remove();

      // Table data (empty rows)
      const data: Array<{ marks?: string; justification?: string; route?: string }> = [];
      const columns = [
        { label: "marks", key: "marks" },
        { label: "justification", key: "justification" },
        { label: "route", key: "route" },
      ];

      // Create table
      const table = d3
        .select(d3Container.current)
        .append("table")
        .attr("class", "min-w-full border border-gray-300 rounded-md table-auto");

      // Table header
      const thead = table.append("thead");
      thead
        .append("tr")
        .selectAll("th")
        .data(columns)
        .enter()
        .append("th")
        .text((d) => d.label)
        .attr("class", "px-4 py-2 border-b bg-gray-100 text-left");

      // Table body (empty rows)
      table.append("tbody");
    }
  }, []);

  return (
    <div className="flex flex-col items-center justify-center min-h-screen">
      <h1 className="text-2xl font-bold mb-6">Marks Table</h1>
      <div ref={d3Container} className="w-full max-w-2xl" />
    </div>
  );
}
