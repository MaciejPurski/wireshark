/* gui_prefs.h
 * Definitions for column preferences window
 *
 * $Id: column_prefs.h,v 1.1 2000/01/10 01:43:58 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

GtkWidget           *column_prefs_show(void);
void                 column_prefs_ok(GtkWidget *);
void                 column_prefs_save(GtkWidget *);
void                 column_prefs_cancel(GtkWidget *);
void                 column_prefs_delete(GtkWidget *);
