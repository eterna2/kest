'use client';

import React from 'react';
import { RoughNotation } from 'react-rough-notation';
import { useTheme } from './ThemeProvider';

interface SketchyHighlightProps {
  children: React.ReactNode;
  type?: 'underline' | 'box' | 'circle' | 'highlight' | 'strike-through' | 'crossed-off';
  color?: string;
  strokeWidth?: number;
  padding?: number | [number, number, number, number];
  animationDuration?: number;
}

export default function SketchyHighlight({ 
  children, 
  type = 'highlight', 
  color = '#fce4e4', // secondary-container default for highlight
  ...props 
}: SketchyHighlightProps) {
  const { theme, mounted } = useTheme();
  
  // RoughNotation needs an inline block or block to render correctly usually, but we pass children
  return (
    <RoughNotation 
        type={type} 
        show={mounted && theme === 'scratchpad'} 
        color={color} 
        {...props}
    >
        {children}
    </RoughNotation>
  );
}
