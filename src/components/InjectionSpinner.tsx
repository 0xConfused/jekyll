// SPDX-License-Identifier: AGPL-3.0-or-later

import React from 'react';

interface InjectionSpinnerProps {
  className?: string;
  size?: number | string;
}

export const InjectionSpinner: React.FC<InjectionSpinnerProps> = ({
  className = 'w-10 h-10 text-[#c30800]',
  size,
}) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 100 100"
      width={size}
      height={size}
      fill="none"
      stroke="currentColor"
      className={`animate-spin select-none ${className}`}
      aria-label="Processing..."
      role="status"
    >
      {/* Outer Enclosing Ring */}
      <circle
        cx="50"
        cy="50"
        r="44"
        fill="none"
        stroke="currentColor"
        strokeWidth="6.5"
      />

      {/* Internal Injection Branching Circuit rotated -35 deg */}
      <g transform="rotate(-35, 50, 50)">
        {/* Base Socket Foot Tab */}
        <rect
          x="43"
          y="77"
          width="14"
          height="7"
          fill="currentColor"
          stroke="none"
        />

        {/* Main Base Connector Housing */}
        <rect
          x="36"
          y="59"
          width="28"
          height="18"
          fill="none"
          stroke="currentColor"
          strokeWidth="6"
          strokeLinejoin="miter"
        />

        {/* Central Injection Trunk */}
        <line
          x1="50"
          y1="59"
          x2="50"
          y2="30.5"
          stroke="currentColor"
          strokeWidth="6"
          strokeLinecap="square"
        />

        {/* Left Arm Fork */}
        <path
          d="M 50 51.5 L 26.5 51.5 L 26.5 40"
          fill="none"
          stroke="currentColor"
          strokeWidth="6"
          strokeLinejoin="miter"
          strokeLinecap="square"
        />

        {/* Right Arm Fork */}
        <path
          d="M 50 51.5 L 73.5 51.5 L 73.5 40"
          fill="none"
          stroke="currentColor"
          strokeWidth="6"
          strokeLinejoin="miter"
          strokeLinecap="square"
        />

        {/* Left Terminal Node */}
        <circle
          cx="26.5"
          cy="32.5"
          r="8"
          fill="none"
          stroke="currentColor"
          strokeWidth="6"
        />

        {/* Center Terminal Node */}
        <circle
          cx="50"
          cy="22.5"
          r="8"
          fill="none"
          stroke="currentColor"
          strokeWidth="6"
        />

        {/* Right Terminal Node */}
        <circle
          cx="73.5"
          cy="32.5"
          r="8"
          fill="none"
          stroke="currentColor"
          strokeWidth="6"
        />
      </g>
    </svg>
  );
};
