import React, { useState } from 'react'
import Image from 'next/image'

const ERROR_IMG_SRC =
  'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iODgiIGhlaWdodD0iODgiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgc3Ryb2tlPSIjMDAwIiBzdHJva2UtbGluZWpvaW49InJvdW5kIiBvcGFjaXR5PSIuMyIgZmlsbD0ibm9uZSIgc3Ryb2tlLXdpZHRoPSIzLjciPjxyZWN0IHg9IjE2IiB5PSIxNiIgd2lkdGg9IjU2IiBoZWlnaHQ9IjU2IiByeD0iNiIvPjxwYXRoIGQ9Im0xNiA1OCAxNi0xOCAzMiAzMiIvPjxjaXJjbGUgY3g9IjUzIiBjeT0iMzUiIHI9IjciLz48L3N2Zz4KCg=='

export function ImageWithFallback(props: React.ImgHTMLAttributes<HTMLImageElement>) {
  const [didError, setDidError] = useState(false)

  const handleError = () => {
    setDidError(true)
  }

  // next/image needs numeric sizes; without both, fall back to fill mode.
  const { src, alt, style, className, width, height, ...rest } = props

  const parsedWidth = typeof width === 'string' && !isNaN(Number(width)) ? Number(width) : undefined
  const parsedHeight = typeof height === 'string' && !isNaN(Number(height)) ? Number(height) : undefined

  const isFill = !parsedWidth || !parsedHeight
  const imageSrc = typeof src === 'string' ? src : ERROR_IMG_SRC

  return didError ? (
    <div
      className={`inline-block bg-gray-100 text-center align-middle ${className ?? ''}`}
      style={style}
    >
      <div className="relative flex items-center justify-center w-full h-full">
        <Image 
          src={ERROR_IMG_SRC} 
          alt="Error loading image" 
          width={parsedWidth ?? 88}
          height={parsedHeight ?? 88}
          {...rest} 
        />
      </div>
    </div>
  ) : (
    <div className={isFill ? 'relative w-full h-full' : undefined} style={style}>
      <Image 
        src={imageSrc} 
        alt={alt ?? ''} 
        className={className} 
        fill={isFill}
        width={isFill ? undefined : parsedWidth}
        height={isFill ? undefined : parsedHeight}
        {...rest} 
        onError={handleError} 
      />
    </div>
  )
}