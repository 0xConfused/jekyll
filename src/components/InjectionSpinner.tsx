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
      viewBox="0 0 512 512"
      width={size}
      height={size}
      fill="none"
      stroke="currentColor"
      className={`animate-spin select-none ${className}`}
      aria-label="Processing..."
      role="status"
    >
      <g transform="translate(-6.267, -0.691)">
        <ellipse
          paintOrder="fill"
          fill="none"
          stroke="currentColor"
          strokeWidth={31}
          cx="262.267"
          cy="256.691"
          rx="216.861"
          ry="216.861"
        />
        <ellipse
          fill="none"
          stroke="currentColor"
          strokeWidth={21}
          cx="143.988"
          cy="225.816"
          rx="30.672"
          ry="30.672"
        />
        <ellipse
          fill="none"
          stroke="currentColor"
          strokeWidth={21}
          cx="233.844"
          cy="186.936"
          rx="30.672"
          ry="30.672"
        />
        <ellipse
          fill="none"
          stroke="currentColor"
          strokeWidth={21}
          cx="323.7"
          cy="149.784"
          rx="30.672"
          ry="30.672"
        />
        <path
          fill="none"
          stroke="currentColor"
          strokeLinecap="round"
          strokeWidth={22}
          d="M 248.532 223.224 L 284.82 307.463"
        />
        <path
          fill="none"
          stroke="currentColor"
          strokeLinecap="round"
          strokeWidth={22}
          d="M 184.79 315.191 L 362.02 238.993"
          transform="translate(273.156, 277.223) matrix(-1, 0, 0, -1, 0.000012, -0.000016) translate(-273.156, -277.223)"
        />
        <path
          fill="none"
          stroke="currentColor"
          strokeLinecap="round"
          strokeWidth={22}
          d="M 157.812 256.704 L 182.868 315.455"
        />
        <path
          fill="none"
          stroke="currentColor"
          strokeLinecap="round"
          strokeWidth={22}
          d="M 336.228 179.16 L 361.284 237.911"
        />
        <path
          fill="none"
          stroke="currentColor"
          strokeLinecap="round"
          strokeWidth={22}
          d="M 251.988 331.224 L 271.465 377.719"
        />
        <path
          fill="none"
          stroke="currentColor"
          strokeLinecap="round"
          strokeWidth={22}
          d="M 325.07 299.04 L 345.732 346.127"
        />
        <path
          fill="none"
          stroke="currentColor"
          strokeLinecap="round"
          strokeWidth={22}
          d="M 252.543 329.823 L 324.243 299.039"
        />
        <path
          fill="none"
          stroke="currentColor"
          strokeLinecap="round"
          strokeWidth={22}
          d="M 272.199 378.152 L 345.084 346.775"
        />
        <path
          fill="none"
          stroke="currentColor"
          strokeLinecap="round"
          strokeWidth={22}
          d="M 309.241 363.316 L 321.213 392.233"
        />
        <path
          fill="none"
          stroke="currentColor"
          strokeLinecap="round"
          strokeWidth={22}
          d="M 299.563 401.827 L 343.924 382.754"
        />
      </g>
    </svg>
  );
};
