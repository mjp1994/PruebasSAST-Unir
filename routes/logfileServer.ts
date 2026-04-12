/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

const BASE_DIR = path.resolve('logs')

const ALLOWED_LOG_FILES = new Set([
  'application.log',
  'access.log',
  'error.log',
  'support.log',
  'support.kdbx',
  'package.json.bak',
])

export function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file || typeof file !== 'string') {
      res.status(400)
      return next(new Error('Invalid filename'))
    }

    if (file.includes('/') || file.includes('\\')) {
      res.status(403)
      return next(new Error('File names cannot contain path separators'))
    }

    if (!ALLOWED_LOG_FILES.has(file)) {
      res.status(403)
      return next(new Error('Access to this log file is not allowed'))
    }

    const targetPath = path.resolve(BASE_DIR, file)

    if (!targetPath.startsWith(BASE_DIR + path.sep)) {
      res.status(403)
      return next(new Error('Access outside of allowed directory is forbidden'))
    }

    res.sendFile(targetPath, (err) => {
      if (err) {
        res.status(404).send('Log file not found')
      }
    })
  }
}