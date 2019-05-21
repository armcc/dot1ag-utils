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

/***************************/
/*       HEADER            */
/***************************/
#include <errno.h>
#include <oam_db.h>
#include <oam_entity.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static struct oam_entity_info *oam_db = NULL;
static int32_t participant = 0;
#define MAX_MEP_IN_MEG 8191

/**************************************************************************/
/*! \fn oam_insert_entity(struct oam_entity_info* entity)
**************************************************************************
*  \brief adding an entity to the database if the same entity does not exist.
          entity is identified by MAC address.
*  \param[in] entity - targeting entity info.
*  \return the entity pointer from database or NULL pointer when failed
*/
struct oam_entity_info* oam_insert_entity(struct oam_entity_info* entity)
{
    if (NULL == entity)
    {
        return NULL;
    }

    if (participant >= MAX_MEP_IN_MEG)
    {
        return NULL;
    }
    struct oam_entity_info *curr = NULL;
    curr = oam_find_entity_by_mac(entity->info.mac);
    if (NULL != curr)
    {
        return curr;
    }
    curr = oam_db;
    if (NULL == oam_db)
    {
        oam_db = (struct oam_entity_info*)
                 calloc(1, sizeof(struct oam_entity_info));
        if (NULL == oam_db)
        {
            printf("cannot creat entity database\n");
            return NULL;
        }
        memcpy (oam_db, entity, sizeof(struct oam_entity_info));
        oam_db->next = NULL;
        curr = oam_db;
    }
    else
    {
        struct oam_entity_info *new_entity = (struct oam_entity_info*)
                                        malloc(sizeof (struct oam_entity_info));
        if (NULL == new_entity)
        {
            printf("cannot creat entity database\n");
            return NULL;
        }

        while (NULL != curr->next)
        {
            curr = curr->next;
        }
        memcpy( new_entity, entity, sizeof (struct oam_entity_info) );
        new_entity->next = NULL;
        curr->next = new_entity;
    }
    ++participant;
    return curr;
}

/**************************************************************************/
/*! \fn oam_delete_db
**************************************************************************
*  \brief clean up the database and free the memory
*  \return 1 for success
*/
int32_t oam_delete_db()
{
    struct oam_entity_info *curr = oam_db;
    while (NULL != curr)
    {
        struct oam_entity_info *tmp = curr->next;
        free (curr);
        curr = tmp;
    }
    participant = 0;
    oam_db = NULL;
    return 1;
}

/**************************************************************************/
/*! \fn oam_delete_entity(const uint8_t * const mac)
**************************************************************************
*  \brief loop through the database and remove the entity if a matched MAC
          address was found.
*  \param[in] mac - MAC address of the targeting entity
*  \return 1 when success or 0 when failed
*/
int32_t oam_delete_entity(const uint8_t * const mac)
{
    if (NULL == mac)
    {
        return 0;
    }
    struct oam_entity_info *prev = NULL,
                           *curr = oam_db;

    while (curr)
    {
        if (0 == memcmp(&curr->info.mac, mac, ETH_MAC_HDR_LENGTH))
        {
            if (NULL == prev)
            {
                struct oam_entity_info *tmp = curr;
                curr = curr->next;
                oam_db = curr;
                free (tmp);
                --participant;
            }
            else
            {
                struct oam_entity_info *tmp = curr;
                prev->next = curr->next;
                curr = curr->next;
                free (tmp);
                --participant;
            }
        }
        else
        {
            prev = curr;
            curr = curr->next;
        }
    }
    if (participant < 0)
    {
        return 0;
    }
    return 1;
}

/**************************************************************************/
/*! \fn oam_find_entity_by_mac(const uint8_t * const mac)
**************************************************************************
*  \brief loop through the database and return the entity if a matched MAC
          address was found.
*  \param[in] mac - MAC address of the targeting entity
*  \return entity pointer from database or a NULL pointer
*/
struct oam_entity_info* oam_find_entity_by_mac(const uint8_t *const mac)
{
    struct oam_entity_info *curr = oam_db;
    if (NULL == mac)
    {
        fprintf(stderr,"invalid input argument\n");
        return NULL;
    }
    while (NULL != curr)
    {
        if (0 == memcmp(curr->info.mac, mac, ETH_MAC_HDR_LENGTH))
        {
            return curr;
        }
        curr = curr->next;
    }
    return NULL;
}

/**************************************************************************/
/*! \fn oam_find_entity_by_mepid(const uint16_t mepid)
**************************************************************************
*  \brief loop through the database and return the first entity with a matching
          ID
*  \param[in] mepid - targeting MEP identifier
*  \return entity pointer from database or a NULL pointer
*/
struct oam_entity_info* oam_find_entity_by_mepid(const uint16_t mepid)
{
	struct oam_entity_info *curr = oam_db;
	while (NULL != curr)
	{
		if (curr->info.mep_id == mepid)
		{
			return curr;
		}
	}
	return NULL;
}

/**************************************************************************/
/*! \fn oam_get_number_participant
**************************************************************************
*  \brief return the number of entities stored in database
*  \return number of entities stored in database
*/
int32_t oam_get_number_participant(void)
{
    return participant;
}
