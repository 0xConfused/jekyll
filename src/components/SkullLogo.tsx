// SPDX-License-Identifier: AGPL-3.0-or-later

import React from 'react';

interface SkullLogoProps {
  className?: string;
  size?: number;
  alt?: string;
}

export const SkullLogo: React.FC<SkullLogoProps> = ({
  className = '',
  size = 42,
  alt = '0xCONFUSED Emblem',
}) => {
  return (
    <div
      style={{ width: `${size}px`, height: `${size}px` }}
      className={`shrink-0 flex items-center justify-center select-none ${className}`}
    >
      <img
        src="/skull-logo.png"
        alt={alt}
        width={size}
        height={size}
        className="w-full h-full object-contain pointer-events-none select-none"
        draggable={false}
      />
    </div>
  );
};
