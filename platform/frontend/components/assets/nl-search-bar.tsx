"use client";

import React, { useState } from "react";
import { Search, Loader2, X, Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { aiApi } from "@/lib/api";
import type { FilterChip, AISearchResponse } from "@/types";

interface NLSearchBarProps {
  context?: "assets" | "findings";
  onFiltersChange: (filters: Record<string, unknown>) => void;
  placeholder?: string;
}

export function NLSearchBar({ context = "assets", onFiltersChange, placeholder }: NLSearchBarProps) {
  const [query, setQuery] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [chips, setChips] = useState<FilterChip[]>([]);
  const [error, setError] = useState<string | null>(null);

  const handleSearch = async () => {
    if (!query.trim()) return;
    setIsLoading(true);
    setError(null);

    try {
      const response = await aiApi.search(query, context) as AISearchResponse;
      setChips(response.chips);
      onFiltersChange(response.filters);
    } catch (err) {
      setError("Failed to process query. Try again.");
    } finally {
      setIsLoading(false);
    }
  };

  const removeChip = (key: string) => {
    const updatedChips = chips.filter((c) => c.key !== key);
    setChips(updatedChips);

    // Rebuild filters from remaining chips
    const filters: Record<string, unknown> = {};
    updatedChips.forEach((chip) => {
      filters[chip.key] = chip.value;
    });
    onFiltersChange(filters);
  };

  const clearAll = () => {
    setChips([]);
    setQuery("");
    onFiltersChange({});
  };

  return (
    <div className="space-y-2">
      <div className="flex gap-2">
        <div className="relative flex-1">
          <Sparkles className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-blue-400" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSearch()}
            placeholder={
              placeholder ??
              `Ask AI: "show staging subdomains with auth issues"...`
            }
            className="pl-9 bg-zinc-900 border-zinc-700 focus:border-blue-500"
          />
        </div>
        <Button
          onClick={handleSearch}
          disabled={isLoading || !query.trim()}
          className="gap-1.5"
          size="default"
        >
          {isLoading ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Search className="h-4 w-4" />
          )}
          Search
        </Button>
        {chips.length > 0 && (
          <Button variant="ghost" size="sm" onClick={clearAll} className="text-zinc-500">
            Clear
          </Button>
        )}
      </div>

      {error && (
        <p className="text-xs text-red-400">{error}</p>
      )}

      {chips.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {chips.map((chip) => (
            <span
              key={chip.key}
              className="inline-flex items-center gap-1 rounded-full border border-blue-500/30 bg-blue-500/10 px-3 py-1 text-xs text-blue-400"
            >
              <span className="font-medium">{chip.label}</span>
              {chip.removable && (
                <button
                  onClick={() => removeChip(chip.key)}
                  className="ml-0.5 rounded-full text-blue-400/60 hover:text-blue-400 transition-colors"
                >
                  <X className="h-3 w-3" />
                </button>
              )}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
