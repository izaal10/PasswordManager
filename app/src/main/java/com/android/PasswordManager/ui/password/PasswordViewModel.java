package com.android.PasswordManager.ui.password;

import android.app.Application;

import androidx.annotation.NonNull;
import androidx.lifecycle.AndroidViewModel;
import androidx.lifecycle.LiveData;

import com.android.PasswordManager.models.ViyCred;
import com.android.PasswordManager.repos.CredsRepository;

import java.util.List;

public class PasswordViewModel extends AndroidViewModel {
    private CredsRepository repository;
    private LiveData<List<ViyCred>> allCreds, mailCreds;

    public PasswordViewModel(@NonNull Application application) {
        super(application);
        repository = new CredsRepository(application);
        allCreds = repository.getAllNotes();
        mailCreds = repository.getAllMails();

    }

    public void insert(ViyCred viyCred) {
        repository.insert(viyCred);
    }

    public void update(ViyCred viyCred) {
        repository.update(viyCred);
    }

    public void delete(ViyCred viyCred) {
        repository.delete(viyCred);
    }

    public void deleteAllNotes() {
        repository.deleteAllNotes();
    }

    public LiveData<List<ViyCred>> getAllCreds() {
        return allCreds;
    }

    public LiveData<List<ViyCred>> getAllMails() {
        return mailCreds;
    }
}