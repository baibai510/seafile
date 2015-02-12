#include "common.h"

#include "seafile-session.h"
#include "log.h"

#include "fsck.h"

typedef struct FsckData {
    gboolean clean;
    SeafRepo *repo;
    GHashTable *existing_blocks;
} FsckData;

typedef enum VerifyType {
    VERIFY_FILE,
    VERIFY_DIR
} VerifyType;

gboolean
fsck_verify_seafobj (SeafFSManager *mgr,
                     const char *store_id,
                     int version,
                     const char *obj_id,
                     VerifyType type,
                     gboolean clean)
{
    gboolean valid = TRUE;
    gboolean io_error = FALSE;

    valid = seaf_fs_manager_object_exists (mgr, store_id,
                                           version, obj_id);
    if (!valid)
        return valid;

    if (type == VERIFY_FILE) {
        valid = seaf_fs_manager_verify_seafile (mgr, store_id, version,
                                                obj_id, TRUE, &io_error);
        if (!valid && !io_error && clean) {
            seaf_message ("Remove curropted file %.8s.\n", obj_id);
            seaf_fs_manager_delete_object (mgr, store_id, version, obj_id);
        }
    } else if (type == VERIFY_DIR) {
        valid = seaf_fs_manager_verify_seafdir (mgr, store_id, version,
                                                obj_id, TRUE, &io_error);
        if (!valid && !io_error && clean) {
            seaf_message ("Remove curropted dir %.8s.\n", obj_id);
            seaf_fs_manager_delete_object (mgr, store_id, version, obj_id);
        }
    }

    return valid || io_error;
}

static int
check_blocks (SeafFSManager *mgr, FsckData *fsck_data, const char *file_id)
{
    SeafRepo *repo = fsck_data->repo;
    Seafile *seafile;
    int i;
    char *block_id;
    int ret = 0;
    int dummy;
    gboolean io_error = FALSE;
    gboolean ok = TRUE;


    seafile = seaf_fs_manager_get_seafile (mgr, repo->store_id, repo->version, file_id);
    if (!seafile) {
        if (fsck_data->clean) {
            seaf_message ("Remove curropted file %.8s.\n", file_id);
            seaf_fs_manager_delete_object (mgr, repo->store_id, repo->version, file_id);
        }
        return -1;
    }

    for (i = 0; i < seafile->n_blocks; ++i) {
        block_id = seafile->blk_sha1s[i];

        if (g_hash_table_lookup (fsck_data->existing_blocks, block_id))
            continue;

        if (!seaf_block_manager_block_exists (seaf->block_mgr,
                                              repo->store_id, repo->version,
                                              block_id)) {
            seaf_message ("Block %s is missing.\n", block_id);
            if (fsck_data->clean) {
                seaf_message ("Remove curropted file %.8s.\n", file_id);
                seaf_fs_manager_delete_object (mgr, repo->store_id, repo->version, file_id);
            }
            ret = -1;
            break;
        }

        // check block integrity, if not remove it
        ok = seaf_block_manager_verify_block (seaf->block_mgr,
                                              repo->store_id, repo->version,
                                              block_id, &io_error);
        if (!ok && !io_error) {
            if (fsck_data->clean) {
                seaf_message ("Block %s is corrupted, remove it.\n", block_id);
                seaf_block_manager_remove_block (seaf->block_mgr,
                                                 repo->store_id, repo->version,
                                                 block_id);
                seaf_message ("Remove curropted file %.8s.\n", file_id);
                seaf_fs_manager_delete_object (mgr, repo->store_id, repo->version, file_id);
            }
            ret = -1;
            break;
        }

        g_hash_table_insert (fsck_data->existing_blocks, g_strdup(block_id), &dummy);
    }

    seafile_unref (seafile);

    return ret;
}

// checked dir must be exists
static char*
fsck_check_dir_recursive (SeafFSManager *mgr,
                          const char *id,
                          FsckData *fsck_data)
{
    SeafDir *dir;
    SeafDir *new_dir;
    GList *p;
    SeafDirent *seaf_dent;
    char *dir_id;
    char *repo_id = fsck_data->repo->store_id;
    int version = fsck_data->repo->version;
    gboolean is_corrupted = FALSE;

    dir = seaf_fs_manager_get_seafdir (mgr, repo_id, version, id);

    for (p = dir->entries; p; p = p->next) {
        seaf_dent = p->data;

        if (S_ISREG(seaf_dent->mode)) {
            if (check_blocks (mgr, fsck_data, seaf_dent->id) < 0) {
                // file curropted, set it empty
                seaf_message ("File %s(%.8s) is curropted, set to empty.\n",
                              seaf_dent->name, seaf_dent->id);
                memcpy (seaf_dent->id, EMPTY_SHA1, 40);
                seaf_dent->size = 0;
                is_corrupted = TRUE;
            }
        } else if (S_ISDIR(seaf_dent->mode)) {
            if (fsck_verify_seafobj (mgr, repo_id, version,
                                     seaf_dent->id, VERIFY_DIR, fsck_data->clean)) {
                dir_id = fsck_check_dir_recursive (mgr, seaf_dent->id, fsck_data);
                if (strcmp (dir_id, seaf_dent->id) != 0) {
                    if (fsck_data->clean) {
                        seaf_message ("Remove curropted dir %.8s.\n", seaf_dent->id);
                        seaf_fs_manager_delete_object (mgr, repo_id, version, seaf_dent->id);
                    }
                    // dir curropted, set it to new dir_id
                    memcpy (seaf_dent->id, dir_id, 41);
                    is_corrupted = TRUE;
                }
                g_free (dir_id);
           } else {
               // dir curropted, set it empty
               seaf_message ("Dir %s(%.8s) is curropted, set to empty.\n",
                             seaf_dent->name, seaf_dent->id);
               memcpy (seaf_dent->id, EMPTY_SHA1, 40);
               is_corrupted = TRUE;
           }
        }
    }

    if (is_corrupted) {
        new_dir = seaf_dir_new (NULL, dir->entries, version);
        seaf_dir_save (mgr, repo_id, version, new_dir);
        dir_id = g_strdup (new_dir->dir_id);
        seaf_dir_free (new_dir);
        dir->entries = NULL;
    } else {
        dir_id = g_strdup (dir->dir_id);
    }

    seaf_dir_free (dir);

    return dir_id;
}

static gint
compare_commit_by_ctime (gconstpointer a, gconstpointer b)
{
    const SeafCommit *commit_a = a;
    const SeafCommit *commit_b = b;

    return (commit_b->ctime - commit_a->ctime);
}

static gboolean
fsck_get_repo_commit (const char *repo_id, int version,
                      const char *obj_id, void *commit_list)
{
    void *data = NULL;
    int data_len;
    GList **cur_list = (GList **)commit_list;

    int ret = seaf_obj_store_read_obj (seaf->commit_mgr->obj_store, repo_id,
                                       version, obj_id, &data, &data_len);
    if (ret < 0 || data == NULL)
        return TRUE;

    SeafCommit *cur_commit = seaf_commit_from_data (obj_id, data, data_len);
    if (cur_commit != NULL) {
       *cur_list = g_list_prepend (*cur_list, cur_commit);
    }

    g_free(data);
    return TRUE;
}

static SeafCommit*
cre_commit_from_parent (char *repo_id, SeafCommit *parent, char *new_root_id)
{
    SeafCommit *new_commit = NULL;
    new_commit = seaf_commit_new (NULL, repo_id, new_root_id,
                                  parent->creator_name, parent->creator_id,
                                  "repaired by system", 0);
    if (new_commit) {
        new_commit->parent_id = g_strdup (parent->commit_id);
        new_commit->repo_name = g_strdup (parent->repo_name);
        new_commit->repo_desc = g_strdup (parent->repo_desc);
        new_commit->encrypted = parent->encrypted;
        if (new_commit->encrypted) {
            new_commit->enc_version = parent->enc_version;
            if (new_commit->enc_version >= 1)
                new_commit->magic = g_strdup (parent->magic);
            if (new_commit->enc_version == 2)
                new_commit->random_key = g_strdup (parent->random_key);
        }
        new_commit->repo_category = g_strdup (parent->repo_category);
        new_commit->no_local_history = parent->no_local_history;
        new_commit->version = parent->version;
        new_commit->repaired = TRUE;
    }

    return new_commit;
}

static SeafRepo*
get_available_repo (char *repo_id, gboolean clean)
{
    GList *commit_list = NULL;
    GList *temp_list = NULL;
    SeafCommit *temp_commit = NULL;
    SeafBranch *branch = NULL;
    SeafRepo *repo = NULL;
    SeafVirtRepo *vinfo = NULL;

    seaf_message ("Get available repo for repo id %.8s.\n", repo_id);

    seaf_obj_store_foreach_obj (seaf->commit_mgr->obj_store, repo_id,
                                1, fsck_get_repo_commit, &commit_list);

    if (commit_list == NULL) {
        seaf_warning ("Get available repo for repo id %.8s failed: "
                      "no commit info.\n", repo_id);
        return NULL;
    }

    commit_list = g_list_sort (commit_list, compare_commit_by_ctime);

    repo = seaf_repo_new (repo_id, NULL, NULL);
    if (repo == NULL) {
        seaf_warning ("Get available repo for repo id %.8s failed: "
                      "create repo failed.\n", repo_id);
        goto out;
    }

    vinfo = seaf_repo_manager_get_virtual_repo_info (seaf->repo_mgr, repo_id);
    if (vinfo) {
        repo->is_virtual = TRUE;
        memcpy (repo->store_id, vinfo->origin_repo_id, 36);
        seaf_virtual_repo_info_free (vinfo);
    } else {
        repo->is_virtual = FALSE;
        memcpy (repo->store_id, repo->id, 36);
    }

    for (temp_list = commit_list; temp_list; temp_list = temp_list->next) {
        temp_commit = temp_list->data;

        if (!fsck_verify_seafobj (seaf->fs_mgr, repo->store_id,
                                  1, temp_commit->root_id, VERIFY_DIR, clean)) {
            continue;
        }

        branch = seaf_branch_new ("master", repo_id, temp_commit->commit_id);
        if (branch == NULL) {
            continue;
        }
        repo->head = branch;
        seaf_repo_from_commit (repo, temp_commit);
        // find the latest available commit, update to repo,
        // using add branch in case head commit loss in db
        if (seaf_branch_manager_add_branch (seaf->branch_mgr, repo->head) < 0) {
            seaf_warning ("Get available repo for repo id %.8s failed: "
                          "Failed to update branch head.\n", repo_id);
            seaf_repo_unref (repo);
            repo = NULL;
        } else {
            seaf_message ("Find available repo for repo id %.8s, "
                          "reset head commit to %.8s.\n", repo_id,
                          temp_commit->commit_id);
        }
        break;
    }

out:
    for (temp_list = commit_list; temp_list; temp_list = temp_list->next) {
        temp_commit = temp_list->data;
        seaf_commit_unref (temp_commit);
    }
    g_list_free (commit_list);

    return repo;
}

/*
 * check and recover repo, for curropted file or folder set it empty
 */
static void
check_and_recover_repo (SeafRepo *repo, gboolean clean)
{
    FsckData fsck_data;
    SeafCommit *rep_commit;
    SeafCommit *new_commit;

    seaf_message ("Checking file system integrity of repo %s(%.8s)...\n",
                  repo->name, repo->id);

    rep_commit = seaf_commit_manager_get_commit (seaf->commit_mgr, repo->id,
                                                 repo->version, repo->head->commit_id);
    if (!rep_commit) {
        seaf_warning ("Checking file system integrity of repo %s(%.8s) failed: "
                      "fail to get head commit.\n",
                      repo->name, repo->id);
        return;
    }

    memset (&fsck_data, 0, sizeof(fsck_data));
    fsck_data.clean = clean;
    fsck_data.repo = repo;
    fsck_data.existing_blocks = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                       g_free, NULL);

    char *root_id = fsck_check_dir_recursive (seaf->fs_mgr, rep_commit->root_id, &fsck_data);

    g_hash_table_destroy (fsck_data.existing_blocks);

    if (strcmp (root_id, rep_commit->root_id) != 0) {
        // some fs objects curropted for the head commit,
        // create new head commit using the new root_id
        new_commit = cre_commit_from_parent (repo->id, rep_commit, root_id);
        if (new_commit == NULL) {
            seaf_warning ("Failed to recover repo %s(%.8s): create new commit failed.\n",
                          repo->name, repo->id);
        } else {
            seaf_message ("Resetting head of repo %.8s to commit %.8s.\n",
                          repo->id, new_commit->commit_id);
            seaf_branch_set_commit (repo->head, new_commit->commit_id);
            if (seaf_branch_manager_update_branch (seaf->branch_mgr, repo->head) < 0) {
                seaf_warning ("Failed to recover repo %s(%.8s): "
                              "failed to update branch head.\n", repo->name, repo->id);
            } else {
                seaf_commit_manager_add_commit (seaf->commit_mgr, new_commit);
            }
            seaf_commit_unref (new_commit);
        }
    }

    g_free (root_id);
    seaf_commit_unref (rep_commit);
}

int
seaf_fsck (GList *repo_id_list, gboolean clean)
{
    if (!repo_id_list)
        repo_id_list = seaf_repo_manager_get_repo_id_list (seaf->repo_mgr);

    GList *ptr;
    char *repo_id;
    SeafRepo *repo;

    for (ptr = repo_id_list; ptr; ptr = ptr->next) {
        repo_id = ptr->data;

        seaf_message ("Running fsck for repo %.8s.\n", repo_id);

        repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);

        if (!repo) {
            repo = get_available_repo (repo_id, clean);
            if (!repo) {
                seaf_warning ("No available repo for repo id %.8s, recover is failed.\n\n",
                              repo_id);
                continue;
            }
        } else {
            SeafCommit *commit = seaf_commit_manager_get_commit (seaf->commit_mgr, repo->id,
                                                                 repo->version,
                                                                 repo->head->commit_id);
            if (fsck_verify_seafobj (seaf->fs_mgr, repo->store_id, repo->version,
                                     commit->root_id, VERIFY_DIR, clean)) {
                seaf_commit_unref (commit);
            } else {
                // root dir is curropted, get available repo
                seaf_commit_unref (commit);
                seaf_repo_unref (repo);
                repo = get_available_repo (repo_id, clean);
                if (!repo) {
                    seaf_warning ("No available repo for repo id %.8s, recover is failed.\n\n",
                                  repo_id);
                    continue;
                }
            }
        }

        check_and_recover_repo (repo, clean);

        seaf_message ("Fsck finished for repo %.8s.\n\n", repo_id);

        seaf_repo_unref (repo);
    }
    return 0;
}
