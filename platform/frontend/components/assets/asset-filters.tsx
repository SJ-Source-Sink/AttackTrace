"use client";

import React from "react";
import { X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Slider } from "@/components/ui/slider";
import { Separator } from "@/components/ui/separator";
import type { AssetFilters, AssetType } from "@/types";

const ASSET_TYPES: { value: AssetType; label: string }[] = [
  { value: "subdomain", label: "Subdomain" },
  { value: "domain", label: "Domain" },
  { value: "ip", label: "IP Address" },
  { value: "webapp", label: "Web App" },
  { value: "cloud", label: "Cloud Resource" },
];

interface AssetFiltersProps {
  filters: AssetFilters;
  onChange: (filters: AssetFilters) => void;
  onClear: () => void;
}

export function AssetFilterPanel({ filters, onChange, onClear }: AssetFiltersProps) {
  const toggleType = (type: AssetType) => {
    const current = filters.types ?? [];
    const updated = current.includes(type)
      ? current.filter((t) => t !== type)
      : [...current, type];
    onChange({ ...filters, types: updated.length > 0 ? updated : undefined });
  };

  const isTypeSelected = (type: AssetType) => (filters.types ?? []).includes(type);
  const hasFilters =
    (filters.types?.length ?? 0) > 0 ||
    filters.risk_min !== undefined ||
    filters.risk_max !== undefined ||
    filters.has_screenshot === true;

  return (
    <div className="space-y-5 p-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-zinc-300">Filters</h3>
        {hasFilters && (
          <Button variant="ghost" size="sm" onClick={onClear} className="h-7 text-xs gap-1">
            <X className="h-3 w-3" />
            Clear all
          </Button>
        )}
      </div>

      {/* Asset Type */}
      <div className="space-y-2">
        <Label className="text-xs uppercase tracking-wider text-zinc-500">Asset Type</Label>
        <div className="space-y-2">
          {ASSET_TYPES.map((type) => (
            <div key={type.value} className="flex items-center gap-2">
              <Checkbox
                id={`type-${type.value}`}
                checked={isTypeSelected(type.value)}
                onCheckedChange={() => toggleType(type.value)}
              />
              <label
                htmlFor={`type-${type.value}`}
                className="text-sm text-zinc-300 cursor-pointer"
              >
                {type.label}
              </label>
            </div>
          ))}
        </div>
      </div>

      <Separator />

      {/* Screenshots */}
      <div className="space-y-2">
        <Label className="text-xs uppercase tracking-wider text-zinc-500">Screenshots</Label>
        <div className="flex items-center gap-2">
          <Checkbox
            id="has-screenshot"
            checked={filters.has_screenshot === true}
            onCheckedChange={(checked) =>
              onChange({ ...filters, has_screenshot: checked ? true : undefined })
            }
          />
          <label htmlFor="has-screenshot" className="text-sm text-zinc-300 cursor-pointer">
            Has screenshot
          </label>
        </div>
      </div>

      <Separator />

      {/* Risk Score Range */}
      <div className="space-y-3">
        <Label className="text-xs uppercase tracking-wider text-zinc-500">Risk Score</Label>
        <div className="px-1">
          <Slider
            min={0}
            max={100}
            step={5}
            value={[filters.risk_min ?? 0, filters.risk_max ?? 100]}
            onValueChange={([min, max]) =>
              onChange({
                ...filters,
                risk_min: min > 0 ? min : undefined,
                risk_max: max < 100 ? max : undefined,
              })
            }
          />
        </div>
        <div className="flex justify-between text-xs text-zinc-500">
          <span>{filters.risk_min ?? 0}</span>
          <span>{filters.risk_max ?? 100}</span>
        </div>
      </div>

      <Separator />

      {/* Active status */}
      <div className="space-y-2">
        <Label className="text-xs uppercase tracking-wider text-zinc-500">Status</Label>
        <div className="space-y-2">
          {[
            { value: true, label: "Active assets" },
            { value: false, label: "Inactive assets" },
          ].map((opt) => (
            <div key={String(opt.value)} className="flex items-center gap-2">
              <Checkbox
                id={`active-${opt.value}`}
                checked={filters.is_active === opt.value}
                onCheckedChange={(checked) =>
                  onChange({
                    ...filters,
                    is_active: checked ? opt.value : undefined,
                  })
                }
              />
              <label
                htmlFor={`active-${opt.value}`}
                className="text-sm text-zinc-300 cursor-pointer"
              >
                {opt.label}
              </label>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
