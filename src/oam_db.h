
/*
* Copyright (c) 2015
* Author: Ming-Jye Chang
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
*
*    1. Redistributions of source code must retain the above copyright
*       notice, this list of conditions and the following disclaimer.
*    2. Redistributions in binary form must reproduce the above copyright
*       notice, this list of conditions and the following disclaimer in the
*       documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
* TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
* PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
* LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef OAM_DB_H
#define OAM_DB_H

/***************************/
/*       HEADER            */
/***************************/
#include <oam_entity.h>

#ifdef __cplusplus
extern "C" {
#endif
/**************************************************************************/
/*! \fn oam_delete_db
**************************************************************************
*  \brief clean up the database and free the memory
*  \return 1 for success
*/
int32_t oam_delete_db();

/**************************************************************************/
/*! \fn oam_delete_entity(const uint8_t * const mac)
**************************************************************************
*  \brief loop through the database and remove the entity if a matched MAC
          address was found.
*  \param[in] mac - MAC address of the targeting entity
*  \return 1 when success or 0 when failed
*/
int32_t oam_delete_entity(const uint8_t * const mac);

/**************************************************************************/
/*! \fn oam_insert_entity(struct oam_entity_info* entity)
**************************************************************************
*  \brief adding an entity to the database if the same entity does not exist.
          entity is identified by MAC address.
*  \param[in] entity - targeting entity info.
*  \return the entity pointer from database or NULL pointer when failed
*/
struct oam_entity_info* oam_insert_entity(struct oam_entity_info* entity);

/**************************************************************************/
/*! \fn oam_find_entity_by_mac(const uint8_t * const mac)
**************************************************************************
*  \brief loop through the database and return the entity if a matched MAC
          address was found.
*  \param[in] mac - MAC address of the targeting entity
*  \return entity pointer from database or a NULL pointer
*/
struct oam_entity_info* oam_find_entity_by_mac(const uint8_t *const mac);

/**************************************************************************/
/*! \fn oam_find_entity_by_mepid(const uint16_t mepid)
**************************************************************************
*  \brief loop through the database and return the first entity with a matching
          ID
*  \param[in] mepid - targeting MEP identifier
*  \return entity pointer from database or a NULL pointer
*/
struct oam_entity_info* oam_find_entity_by_mepid(const uint16_t mepid);

/**************************************************************************/
/*! \fn oam_get_number_participant
**************************************************************************
*  \brief return the number of entities stored in database
*  \return number of entities stored in database
*/
int32_t oam_get_number_participant(void);
#ifdef	__cplusplus
}
#endif

#endif	/* OAM_DB_H */

