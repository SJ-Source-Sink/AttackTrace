"use client";

import React, { useState } from "react";
import { Send } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { useAddFindingComment } from "@/hooks/use-findings";
import { formatRelativeTime } from "@/lib/utils";
import type { FindingComment } from "@/types";

interface FindingCommentsProps {
  findingId: string;
  comments: FindingComment[];
}

function getInitials(name: string): string {
  return name
    .split(" ")
    .map((n) => n[0])
    .join("")
    .toUpperCase()
    .slice(0, 2);
}

export function FindingComments({ findingId, comments }: FindingCommentsProps) {
  const [content, setContent] = useState("");
  const { mutate: addComment, isPending } = useAddFindingComment();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!content.trim()) return;
    addComment({ id: findingId, content: content.trim() });
    setContent("");
  };

  return (
    <div className="space-y-4">
      <h3 className="text-sm font-semibold text-zinc-300">
        Comments {comments.length > 0 && <span className="text-zinc-500">({comments.length})</span>}
      </h3>

      {comments.length === 0 ? (
        <p className="text-sm text-zinc-600 py-2">No comments yet. Be the first to comment.</p>
      ) : (
        <div className="space-y-3">
          {comments.map((comment) => (
            <div key={comment.id} className="flex gap-3">
              <Avatar className="h-7 w-7 shrink-0">
                <AvatarFallback className="text-xs">
                  {getInitials(comment.author.full_name)}
                </AvatarFallback>
              </Avatar>
              <div className="flex-1 min-w-0">
                <div className="flex items-baseline gap-2 mb-1">
                  <span className="text-sm font-medium text-zinc-300">
                    {comment.author.full_name}
                  </span>
                  <span className="text-xs text-zinc-600">
                    {formatRelativeTime(comment.created_at)}
                  </span>
                </div>
                <p className="text-sm text-zinc-400 leading-relaxed">{comment.content}</p>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Comment form */}
      <form onSubmit={handleSubmit} className="space-y-2">
        <Textarea
          placeholder="Add a comment..."
          value={content}
          onChange={(e) => setContent(e.target.value)}
          rows={3}
          className="resize-none"
        />
        <div className="flex justify-end">
          <Button
            type="submit"
            size="sm"
            disabled={isPending || !content.trim()}
            className="gap-1.5"
          >
            <Send className="h-3.5 w-3.5" />
            Comment
          </Button>
        </div>
      </form>
    </div>
  );
}
