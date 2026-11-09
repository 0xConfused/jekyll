// SPDX-License-Identifier: AGPL-3.0-or-later

import React, { useState, useEffect, useRef } from 'react';
import { Upload, FileCode, Check, Trash2, Hash, Eye } from 'lucide-react';
import { computeSha256, formatBytes } from '../utils/cryptoUtils';

interface HtmlUploadCardProps {
  value: string;
  fileName: string;
  onFileLoaded: (content: string, name: string) => void;
  onClear: () => void;
  onPreview?: () => void;
  isPreviewActive?: boolean;
}

export const HtmlUploadCard: React.FC<HtmlUploadCardProps> = ({
  value,
  fileName,
  onFileLoaded,
  onClear,
  onPreview,
  isPreviewActive = false,
}) => {
  const [sha256, setSha256] = useState<string>('');
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    let active = true;
    if (value) {
      computeSha256(value).then((hash) => {
        if (active) setSha256(hash);
      });
    } else {
      setSha256('');
    }
    return () => {
      active = false;
    };
  }, [value]);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const text = (event.target?.result as string) || '';
      onFileLoaded(text, file.name);
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const text = (event.target?.result as string) || '';
      onFileLoaded(text, file.name);
    };
    reader.readAsText(file);
  };

  const linesCount = value ? value.split('\n').length : 0;
  const byteSize = value ? new TextEncoder().encode(value).length : 0;
  const hasFile = Boolean(value && fileName);

  return (
    <div className="w-full bg-[#141414] border border-[#383838] flex flex-col h-auto">
      {/* Card Header */}
      <div className="px-3 sm:px-4 py-2.5 bg-[#141414] backdrop-blur-sm bg-gradient-to-r from-[#c30800]/10 via-transparent to-transparent border-b border-[#383838] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 bg-[#c30800] shrink-0" />
          <h2 className="text-xs font-mono font-bold tracking-wider text-[#f0f0f0]">
            INPUT 1: HTML DOCUMENT
          </h2>
        </div>

        <div className="flex items-center gap-1.5">
          {hasFile && (
            <div className="flex items-center gap-1.5">
              <button
                type="button"
                onClick={onPreview}
                className={`px-2 py-0.5 text-[11px] font-mono border flex items-center gap-1 transition-colors cursor-pointer ${
                  isPreviewActive
                    ? 'border-[#c30800] bg-[#262626] text-[#f3f3f7] font-bold shadow-sm'
                    : 'border-[#383838] bg-[#1a1a1a] hover:bg-[#262626] text-[#8c8c8c] hover:text-[#f0f0f0]'
                }`}
                title="Preview uploaded HTML in the output box"
              >
                <Eye className="w-3 h-3 text-[#c30800]" />
                <span>PREVIEW</span>
              </button>
              <button
                type="button"
                onClick={onClear}
                className="px-2 py-0.5 text-[11px] font-mono border border-[#383838] bg-[#1a1a1a] hover:bg-[#262626] text-[#8c8c8c] hover:text-[#f0f0f0] flex items-center gap-1 transition-colors"
              >
                <Trash2 className="w-3 h-3 text-[#c30800]" />
                <span>REMOVE</span>
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Main Dropzone / File Info Body */}
      <div className="p-3 sm:p-4 flex flex-col">
        {!hasFile ? (
          /* Empty Dropzone State */
          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed p-6 text-center cursor-pointer transition-all flex flex-col items-center justify-center ${
              isDragging
                ? 'border-[#c30800] bg-[#1f1414]'
                : 'border-[#383838] hover:border-[#c30800] hover:bg-[#1a1a1a]'
            }`}
          >
            <Upload className="w-8 h-8 mb-2 text-[#c30800]" />
            <span className="font-mono text-xs font-bold text-[#f0f0f0] tracking-wider uppercase">
              Click or drag &amp; drop HTML document here
            </span>
            <span className="font-mono text-[11px] text-[#737373] mt-1">
              Supported file types: .html, .htm, .xhtml
            </span>
          </div>
        ) : (
          /* File Loaded State */
          <div className="space-y-3">
            <div className="p-3 bg-[#0d0d0d] border border-[#383838] flex items-center justify-between gap-3">
              <div className="flex items-center gap-3 min-w-0">
                <div className="p-2 bg-[#1a1a1a] border border-[#2e2e2e] text-[#c30800] shrink-0">
                  <FileCode className="w-6 h-6 text-[#c30800]" />
                </div>
                <div className="flex flex-col min-w-0">
                  <span className="font-mono text-xs font-bold text-[#f0f0f0] truncate" title={fileName}>
                    {fileName}
                  </span>
                  <span className="font-mono text-[11px] text-[#8c8c8c]">
                    {formatBytes(byteSize)} &bull; {linesCount} lines
                  </span>
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <span className="inline-flex items-center gap-1 text-[11px] font-mono text-[#f0f0f0] bg-[#1a1a1a] border border-[#383838] px-2 py-0.5">
                  <Check className="w-3 h-3 text-[#c30800]" />
                  <span>LOADED</span>
                </span>
              </div>
            </div>

            {/* SHA-256 Checksum */}
            <div className="p-2 bg-[#1a1a1a] border border-[#2e2e2e] text-[11px] font-mono text-[#8c8c8c] flex items-center gap-2">
              <Hash className="w-3 h-3 text-[#c30800] shrink-0" />
              <span className="text-[#737373]">SHA-256:</span>
              <span className="text-[#f0f0f0] truncate select-all">{sha256}</span>
            </div>
          </div>
        )}

        <input
          type="file"
          ref={fileInputRef}
          onChange={handleFileChange}
          accept=".html,.htm,.xhtml"
          className="hidden"
        />
      </div>
    </div>
  );
};
