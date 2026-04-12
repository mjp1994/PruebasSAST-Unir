/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

const BASE_DIR = path.resolve('ftp/quarantine')

const ALLOWED_QUARANTINE_FILES = new Set([
  'suspicious_file.exe',
  'malware_sample.pdf',
  'quarantine_report.txt',
  'eicar.com',
])

export function serveQuarantineFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file || typeof file !== 'string' || file.trim() === '') {
      res.status(400)
      return next(new Error('Invalid or missing filename'))
    }

    if (
        file.includes('/') ||
        file.includes('\\') ||
        file.includes('..') ||
        file.includes('%2e%2e') ||
        file.includes('....') ||
        file.startsWith('/') ||
        file.startsWith('\\')
    ) {
      res.status(403)
      return next(new Error('Invalid characters in filename'))
    }

    if (ALLOWED_QUARANTINE_FILES.size > 0 && !ALLOWED_QUARANTINE_FILES.has(file)) {
      res.status(403)
      return next(new Error('This file is not available in quarantine'))
    }

    const targetPath = path.resolve(BASE_DIR, file)

    if (!targetPath.startsWith(BASE_DIR + path.sep)) {
      res.status(403)
      return next(new Error('Access outside of quarantine directory is forbidden'))
    }

    res.sendFile(targetPath, (err) => {
      if (err) {
        res.status(404).send('File not found in quarantine')
      }
    })
  }
}