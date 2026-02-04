#include "dialog_manage_routes.h"
#include "ui_dialog_manage_routes.h"

#include "3rdparty/qv2ray/v2/ui/widgets/editors/w_JsonEditor.hpp"
#include "3rdparty/qv2ray/v3/components/GeositeReader/GeositeReader.hpp"
#include "main/GuiUtils.hpp"
#include "fmt/Preset.hpp"

#include <QFile>
#include <QLabel>
#include <QMessageBox>
#include <QListWidget>
#include <QLineEdit>
#include <QToolButton>
#include <QUrl>
#include <QDesktopServices>
#include <QJsonObject>

#define REFRESH_ACTIVE_ROUTING(name, obj)           \
    this->active_routing = name;                    \
    setWindowTitle(title_base + " [" + name + "]"); \
    UpdateDisplayRouting(obj, false);

DialogManageRoutes::DialogManageRoutes(QWidget *parent) : QDialog(parent), ui(new Ui::DialogManageRoutes) {
    ui->setupUi(this);
    title_base = windowTitle();

    QStringList qsValue = {""};
    QString dnsHelpDocumentUrl;
    //
    ui->outbound_domain_strategy->addItems(Preset::SingBox::DomainStrategy);
    ui->domainStrategyCombo->addItems(Preset::SingBox::DomainStrategy);
    qsValue += QStringLiteral("prefer_ipv4 prefer_ipv6 ipv4_only ipv6_only").split(" ");
    ui->dns_object->setPlaceholderText(DecodeB64IfValid("ewogICJzZXJ2ZXJzIjogW10sCiAgInJ1bGVzIjogW10sCiAgImZpbmFsIjogIiIsCiAgInN0cmF0ZWd5IjogIiIsCiAgImRpc2FibGVfY2FjaGUiOiBmYWxzZSwKICAiZGlzYWJsZV9leHBpcmUiOiBmYWxzZSwKICAiaW5kZXBlbmRlbnRfY2FjaGUiOiBmYWxzZSwKICAicmV2ZXJzZV9tYXBwaW5nIjogZmFsc2UsCiAgImZha2VpcCI6IHt9Cn0="));
    dnsHelpDocumentUrl = "https://sing-box.sagernet.org/configuration/dns/";
    //
    ui->direct_dns_strategy->addItems(qsValue);
    ui->remote_dns_strategy->addItems(qsValue);
    //
    D_C_LOAD_STRING(custom_route_global)
    //
    connect(ui->use_dns_object, &QCheckBox::stateChanged, this, [=](int state) {
        auto useDNSObject = state == Qt::Checked;
        ui->simple_dns_box->setDisabled(useDNSObject);
        ui->dns_object->setDisabled(!useDNSObject);
    });
    ui->use_dns_object->stateChanged(Qt::Unchecked); // uncheck to uncheck
    connect(ui->dns_document, &QPushButton::clicked, this, [=] {
        MessageBoxInfo("DNS", dnsHelpDocumentUrl);
    });
    connect(ui->format_dns_object, &QPushButton::clicked, this, [=] {
        auto obj = QString2QJsonObject(ui->dns_object->toPlainText());
        if (obj.isEmpty()) {
            MessageBoxInfo("DNS", "invaild json");
        } else {
            ui->dns_object->setPlainText(QJsonObject2QString(obj, false));
        }
    });
    //
    connect(ui->custom_route_edit, &QPushButton::clicked, this, [=] {
        C_EDIT_JSON_ALLOW_EMPTY(custom_route)
    });
    connect(ui->custom_route_global_edit, &QPushButton::clicked, this, [=] {
        C_EDIT_JSON_ALLOW_EMPTY(custom_route_global)
    });
    //
    builtInSchemesMenu = new QMenu(this);
    builtInSchemesMenu->addActions(this->getBuiltInSchemes());
    ui->preset->setMenu(builtInSchemesMenu);

    QString geoipFn = NekoGui::FindCoreAsset("geoip.dat");
    QString geositeFn = NekoGui::FindCoreAsset("geosite.dat");
    //
    const auto sourceStringsDomain = Qv2ray::components::GeositeReader::ReadGeoSiteFromFile(geositeFn);
    directDomainTxt = new AutoCompleteTextEdit("geosite", sourceStringsDomain, this);
    proxyDomainTxt = new AutoCompleteTextEdit("geosite", sourceStringsDomain, this);
    blockDomainTxt = new AutoCompleteTextEdit("geosite", sourceStringsDomain, this);
    //
    const auto sourceStringsIP = Qv2ray::components::GeositeReader::ReadGeoSiteFromFile(geoipFn);
    directIPTxt = new AutoCompleteTextEdit("geoip", sourceStringsIP, this);
    proxyIPTxt = new AutoCompleteTextEdit("geoip", sourceStringsIP, this);
    blockIPTxt = new AutoCompleteTextEdit("geoip", sourceStringsIP, this);

    // --- Simple Route UX improvements ---
    // Placeholders (shown when the box is empty).
    directIPTxt->setPlaceholderText("geoip:cn\ngeoip:private\n1.1.1.0/24");
    proxyIPTxt->setPlaceholderText("geoip:us\n8.8.8.8/32");
    blockIPTxt->setPlaceholderText("geoip:private\n224.0.0.0/3");
    directDomainTxt->setPlaceholderText("geosite:cn\ndomain:example.com\nfull:example.com");
    proxyDomainTxt->setPlaceholderText("geosite:geolocation-!cn\nkeyword:google\nregexp:.*");
    blockDomainTxt->setPlaceholderText("geosite:category-ads-all\ndomain:firebase.io");

    auto countRules = [](const QString &text) -> int {
        int n = 0;
        for (const auto &line: text.split('\n')) {
            const auto t = line.trimmed();
            if (t.isEmpty() || t.startsWith("#")) continue;
            n++;
        }
        return n;
    };
    auto normalizeRulesText = [](const QString &text, bool toLower) -> QString {
        QStringList comments;
        QStringList rules;
        QSet<QString> seen;
        for (const auto &line: text.split('\n')) {
            auto t = line.trimmed();
            if (t.isEmpty()) continue;
            if (t.startsWith("#")) {
                comments << t;
                continue;
            }
            if (toLower) t = t.toLower();
            const auto key = t.toLower();
            if (seen.contains(key)) continue;
            seen.insert(key);
            rules << t;
        }
        rules.sort(Qt::CaseInsensitive);
        if (!comments.isEmpty()) {
            comments.removeDuplicates();
            if (!rules.isEmpty()) comments << "";
        }
        comments.append(rules);
        return comments.join('\n').trimmed();
    };

    // Status hint: geo files for autocomplete.
    auto hint = new QLabel(this);
    hint->setWordWrap(true);
    hint->setTextInteractionFlags(Qt::TextBrowserInteraction);
    hint->setOpenExternalLinks(false);
    hint->setTextFormat(Qt::RichText);
    QStringList missing;
    if (geoipFn.isEmpty()) missing << "geoip.dat";
    if (geositeFn.isEmpty()) missing << "geosite.dat";
    if (!missing.isEmpty()) {
        hint->setStyleSheet("color: #b00020;");
        hint->setText(tr("Tip: autocomplete data not found (%1). You can still type rules manually.").arg(missing.join(", ")));
    } else {
        hint->setStyleSheet("color: #666666;");
        hint->setText(tr("Autocomplete ready: geosite %1, geoip %2.").arg(sourceStringsDomain.size()).arg(sourceStringsIP.size()));
    }
    ui->verticalLayout_2->insertWidget(0, hint);

    auto stats = new QLabel(this);
    stats->setTextInteractionFlags(Qt::TextSelectableByMouse);
    stats->setStyleSheet("color: #666666;");
    ui->horizontalLayout_5->addWidget(stats);

    auto updateStats = [=]() {
        stats->setText(tr("Direct D/IP %1/%2  |  Proxy D/IP %3/%4  |  Block D/IP %5/%6")
                           .arg(countRules(directDomainTxt->toPlainText()))
                           .arg(countRules(directIPTxt->toPlainText()))
                           .arg(countRules(proxyDomainTxt->toPlainText()))
                           .arg(countRules(proxyIPTxt->toPlainText()))
                           .arg(countRules(blockDomainTxt->toPlainText()))
                           .arg(countRules(blockIPTxt->toPlainText())));
    };
    connect(directDomainTxt, &QPlainTextEdit::textChanged, this, updateStats);
    connect(proxyDomainTxt, &QPlainTextEdit::textChanged, this, updateStats);
    connect(blockDomainTxt, &QPlainTextEdit::textChanged, this, updateStats);
    connect(directIPTxt, &QPlainTextEdit::textChanged, this, updateStats);
    connect(proxyIPTxt, &QPlainTextEdit::textChanged, this, updateStats);
    connect(blockIPTxt, &QPlainTextEdit::textChanged, this, updateStats);

    // Action buttons: normalize / clear / help
    auto normalizeBtn = new QToolButton(this);
    normalizeBtn->setText(tr("Normalize"));
    normalizeBtn->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    normalizeBtn->setIcon(QIcon::fromTheme("format-indent-more"));
    ui->horizontalLayout_6->addWidget(normalizeBtn);
    connect(normalizeBtn, &QToolButton::clicked, this, [=] {
        directDomainTxt->setPlainText(normalizeRulesText(directDomainTxt->toPlainText(), true));
        proxyDomainTxt->setPlainText(normalizeRulesText(proxyDomainTxt->toPlainText(), true));
        blockDomainTxt->setPlainText(normalizeRulesText(blockDomainTxt->toPlainText(), true));
        directIPTxt->setPlainText(normalizeRulesText(directIPTxt->toPlainText(), false));
        proxyIPTxt->setPlainText(normalizeRulesText(proxyIPTxt->toPlainText(), false));
        blockIPTxt->setPlainText(normalizeRulesText(blockIPTxt->toPlainText(), false));
    });

    auto clearBtn = new QToolButton(this);
    clearBtn->setText(tr("Clear"));
    clearBtn->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    clearBtn->setIcon(QIcon::fromTheme("edit-clear"));
    ui->horizontalLayout_6->addWidget(clearBtn);
    connect(clearBtn, &QToolButton::clicked, this, [=] {
        if (QMessageBox::question(this, software_name, tr("Clear all simple route rules?")) != QMessageBox::Yes) return;
        directDomainTxt->clear();
        proxyDomainTxt->clear();
        blockDomainTxt->clear();
        directIPTxt->clear();
        proxyIPTxt->clear();
        blockIPTxt->clear();
    });

    auto helpBtn = new QToolButton(this);
    helpBtn->setText(tr("Help"));
    helpBtn->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    helpBtn->setIcon(QIcon::fromTheme("help-browser"));
    ui->horizontalLayout_6->addWidget(helpBtn);
    connect(helpBtn, &QToolButton::clicked, this, [=] {
        const auto msg = tr("One rule per line.\n\n"
                            "Domain rules:\n"
                            "  geosite:cn\n"
                            "  domain:example.com\n"
                            "  full:example.com\n"
                            "  keyword:google\n"
                            "  regexp:.*\n\n"
                            "IP rules:\n"
                            "  geoip:cn\n"
                            "  geoip:private\n"
                            "  1.1.1.0/24\n\n"
                            "Lines starting with # are treated as comments.");
        QMessageBox::information(this, tr("Rule Help"), msg);
    });

    updateStats();
    //
    ui->directTxtLayout->addWidget(directDomainTxt, 0, 0);
    ui->proxyTxtLayout->addWidget(proxyDomainTxt, 0, 0);
    ui->blockTxtLayout->addWidget(blockDomainTxt, 0, 0);
    //
    ui->directIPLayout->addWidget(directIPTxt, 0, 0);
    ui->proxyIPLayout->addWidget(proxyIPTxt, 0, 0);
    ui->blockIPLayout->addWidget(blockIPTxt, 0, 0);
    //
    REFRESH_ACTIVE_ROUTING(NekoGui::dataStore->active_routing, NekoGui::dataStore->routing.get())
    // Load persisted "User 1" draft (if any). Otherwise, initialize it from the
    // currently loaded routing set so the user has a usable starting point.
    LoadUser1DraftFromDataStore();
    if (!user1_snapshot_valid) {
        SaveSimpleRouteSnapshot(&user1_snapshot);
        user1_snapshot_valid = true;
        PersistUser1DraftToDataStore(false);
    }
    // The dialog opens with the active routing set on screen, not "User 1".
    preset_is_user1 = false;

    ADD_ASTERISK(this)
}

DialogManageRoutes::~DialogManageRoutes() {
    // Persist the draft even if user closes the dialog without clicking "OK".
    if (preset_is_user1) {
        SaveSimpleRouteSnapshot(&user1_snapshot);
        user1_snapshot_valid = true;
    }
    PersistUser1DraftToDataStore(true);
    delete ui;
}

void DialogManageRoutes::accept() {
    // Persist "User 1" draft when user applies changes.
    if (preset_is_user1) {
        SaveSimpleRouteSnapshot(&user1_snapshot);
        user1_snapshot_valid = true;
    }
    PersistUser1DraftToDataStore(true);
    D_C_SAVE_STRING(custom_route_global)
    bool routeChanged = false;
    if (NekoGui::dataStore->active_routing != active_routing) routeChanged = true;
    SaveDisplayRouting(NekoGui::dataStore->routing.get());
    NekoGui::dataStore->active_routing = active_routing;
    NekoGui::dataStore->routing->fn = ROUTES_PREFIX + NekoGui::dataStore->active_routing;
    if (NekoGui::dataStore->routing->Save()) routeChanged = true;
    //
    QString info = "UpdateDataStore";
    if (routeChanged) info += "RouteChanged";
    MW_dialog_message(Dialog_DialogManageRoutes, info);
    QDialog::accept();
}

// built in settings

QList<QAction *> DialogManageRoutes::getBuiltInSchemes() {
    QList<QAction *> list;
    auto *user1 = new QAction(tr("User 1"), this);
    connect(user1, &QAction::triggered, this, [=] {
        // "User 1" is a draft slot:
        // - If we are already in User 1, keep updating the snapshot from UI.
        // - If we are in a built-in preset, restore the last User 1 snapshot.
        if (preset_is_user1 || !user1_snapshot_valid) {
            SaveSimpleRouteSnapshot(&user1_snapshot);
            user1_snapshot_valid = true;
            PersistUser1DraftToDataStore(false);
        }
        preset_is_user1 = true;
        LoadSimpleRouteSnapshot(user1_snapshot);
    });
    list.append(user1);
    list.append(this->schemeToAction(tr("Bypass LAN and China"), routing_cn_lan));
    list.append(this->schemeToAction(tr("Global"), routing_global));
    return list;
}

QAction *DialogManageRoutes::schemeToAction(const QString &name, const NekoGui::Routing &scheme) {
    auto *action = new QAction(name, this);
    connect(action, &QAction::triggered, [this, &scheme] {
        // If user is in "User 1" draft, keep it before applying built-in presets.
        if (preset_is_user1) {
            SaveSimpleRouteSnapshot(&user1_snapshot);
            user1_snapshot_valid = true;
            PersistUser1DraftToDataStore(false);
        }
        preset_is_user1 = false;
        this->UpdateDisplayRouting((NekoGui::Routing *) &scheme, true);
    });
    return action;
}

void DialogManageRoutes::UpdateDisplayRouting(NekoGui::Routing *conf, bool qv) {
    //
    directDomainTxt->setPlainText(conf->direct_domain);
    proxyDomainTxt->setPlainText(conf->proxy_domain);
    blockDomainTxt->setPlainText(conf->block_domain);
    //
    blockIPTxt->setPlainText(conf->block_ip);
    directIPTxt->setPlainText(conf->direct_ip);
    proxyIPTxt->setPlainText(conf->proxy_ip);
    //
    CACHE.custom_route = conf->custom;
    ui->def_outbound->setCurrentText(conf->def_outbound);
    //
    if (qv) return;
    //
    ui->sniffing_mode->setCurrentIndex(conf->sniffing_mode);
    ui->outbound_domain_strategy->setCurrentText(conf->outbound_domain_strategy);
    ui->domainStrategyCombo->setCurrentText(conf->domain_strategy);
    ui->use_dns_object->setChecked(conf->use_dns_object);
    ui->dns_object->setPlainText(conf->dns_object);
    ui->dns_routing->setChecked(conf->dns_routing);
    ui->remote_dns->setCurrentText(conf->remote_dns);
    ui->remote_dns_strategy->setCurrentText(conf->remote_dns_strategy);
    ui->direct_dns->setCurrentText(conf->direct_dns);
    ui->direct_dns_strategy->setCurrentText(conf->direct_dns_strategy);
    ui->dns_final_out->setCurrentText(conf->dns_final_out);
}

void DialogManageRoutes::SaveDisplayRouting(NekoGui::Routing *conf) {
    conf->direct_ip = directIPTxt->toPlainText();
    conf->direct_domain = directDomainTxt->toPlainText();
    conf->proxy_ip = proxyIPTxt->toPlainText();
    conf->proxy_domain = proxyDomainTxt->toPlainText();
    conf->block_ip = blockIPTxt->toPlainText();
    conf->block_domain = blockDomainTxt->toPlainText();
    conf->def_outbound = ui->def_outbound->currentText();
    conf->custom = CACHE.custom_route;
    //
    conf->sniffing_mode = ui->sniffing_mode->currentIndex();
    conf->domain_strategy = ui->domainStrategyCombo->currentText();
    conf->outbound_domain_strategy = ui->outbound_domain_strategy->currentText();
    conf->use_dns_object = ui->use_dns_object->isChecked();
    conf->dns_object = ui->dns_object->toPlainText();
    conf->dns_routing = ui->dns_routing->isChecked();
    conf->remote_dns = ui->remote_dns->currentText();
    conf->remote_dns_strategy = ui->remote_dns_strategy->currentText();
    conf->direct_dns = ui->direct_dns->currentText();
    conf->direct_dns_strategy = ui->direct_dns_strategy->currentText();
    conf->dns_final_out = ui->dns_final_out->currentText();
}

void DialogManageRoutes::LoadUser1DraftFromDataStore() {
    user1_snapshot_valid = false;
    auto obj = QString2QJsonObject(NekoGui::dataStore->routing_user1_draft);
    if (obj.isEmpty()) return;

    SimpleRouteSnapshot s{};
    s.direct_ip = obj["direct_ip"].toString();
    s.direct_domain = obj["direct_domain"].toString();
    s.proxy_ip = obj["proxy_ip"].toString();
    s.proxy_domain = obj["proxy_domain"].toString();
    s.block_ip = obj["block_ip"].toString();
    s.block_domain = obj["block_domain"].toString();
    s.def_outbound = obj["def_outbound"].toString();
    s.custom = obj["custom"].toString();
    user1_snapshot = s;
    user1_snapshot_valid = true;
}

void DialogManageRoutes::PersistUser1DraftToDataStore(bool saveNow) {
    if (!user1_snapshot_valid) return;
    QJsonObject obj;
    obj["direct_ip"] = user1_snapshot.direct_ip;
    obj["direct_domain"] = user1_snapshot.direct_domain;
    obj["proxy_ip"] = user1_snapshot.proxy_ip;
    obj["proxy_domain"] = user1_snapshot.proxy_domain;
    obj["block_ip"] = user1_snapshot.block_ip;
    obj["block_domain"] = user1_snapshot.block_domain;
    obj["def_outbound"] = user1_snapshot.def_outbound;
    obj["custom"] = user1_snapshot.custom;
    NekoGui::dataStore->routing_user1_draft = QJsonObject2QString(obj, true);
    if (saveNow) NekoGui::dataStore->Save();
}

void DialogManageRoutes::SaveSimpleRouteSnapshot(SimpleRouteSnapshot *out) const {
    if (out == nullptr) return;
    out->direct_ip = directIPTxt->toPlainText();
    out->direct_domain = directDomainTxt->toPlainText();
    out->proxy_ip = proxyIPTxt->toPlainText();
    out->proxy_domain = proxyDomainTxt->toPlainText();
    out->block_ip = blockIPTxt->toPlainText();
    out->block_domain = blockDomainTxt->toPlainText();
    out->def_outbound = ui->def_outbound->currentText();
    out->custom = CACHE.custom_route;
}

void DialogManageRoutes::LoadSimpleRouteSnapshot(const SimpleRouteSnapshot &in) {
    directIPTxt->setPlainText(in.direct_ip);
    directDomainTxt->setPlainText(in.direct_domain);
    proxyIPTxt->setPlainText(in.proxy_ip);
    proxyDomainTxt->setPlainText(in.proxy_domain);
    blockIPTxt->setPlainText(in.block_ip);
    blockDomainTxt->setPlainText(in.block_domain);
    ui->def_outbound->setCurrentText(in.def_outbound);
    CACHE.custom_route = in.custom;
}

void DialogManageRoutes::on_load_save_clicked() {
    auto w = new QDialog;
    auto layout = new QVBoxLayout;
    w->setLayout(layout);
    auto lineEdit = new QLineEdit;
    layout->addWidget(lineEdit);
    auto list = new QListWidget;
    layout->addWidget(list);
    for (const auto &name: NekoGui::Routing::List()) {
        list->addItem(name);
    }
    connect(list, &QListWidget::currentTextChanged, lineEdit, &QLineEdit::setText);
    auto bottom = new QHBoxLayout;
    layout->addLayout(bottom);
    auto load = new QPushButton;
    load->setText(tr("Load"));
    bottom->addWidget(load);
    auto save = new QPushButton;
    save->setText(tr("Save"));
    bottom->addWidget(save);
    auto remove = new QPushButton;
    remove->setText(tr("Remove"));
    bottom->addWidget(remove);
    auto cancel = new QPushButton;
    cancel->setText(tr("Cancel"));
    bottom->addWidget(cancel);
    connect(load, &QPushButton::clicked, w, [=] {
        auto fn = lineEdit->text();
        if (!fn.isEmpty()) {
            auto r = std::make_unique<NekoGui::Routing>();
            r->load_control_must = true;
            r->fn = ROUTES_PREFIX + fn;
            if (r->Load()) {
                if (QMessageBox::question(nullptr, software_name, tr("Load routing: %1").arg(fn) + "\n" + r->DisplayRouting()) == QMessageBox::Yes) {
                    REFRESH_ACTIVE_ROUTING(fn, r.get()) // temp save to the window
                    w->accept();
                }
            }
        }
    });
    connect(save, &QPushButton::clicked, w, [=] {
        auto fn = lineEdit->text();
        if (!fn.isEmpty()) {
            auto r = std::make_unique<NekoGui::Routing>();
            SaveDisplayRouting(r.get());
            r->fn = ROUTES_PREFIX + fn;
            if (QMessageBox::question(nullptr, software_name, tr("Save routing: %1").arg(fn) + "\n" + r->DisplayRouting()) == QMessageBox::Yes) {
                r->Save();
                REFRESH_ACTIVE_ROUTING(fn, r.get())
                w->accept();
            }
        }
    });
    connect(remove, &QPushButton::clicked, w, [=] {
        auto fn = lineEdit->text();
        if (!fn.isEmpty() && NekoGui::Routing::List().length() > 1) {
            if (QMessageBox::question(nullptr, software_name, tr("Remove routing: %1").arg(fn)) == QMessageBox::Yes) {
                QFile f(ROUTES_PREFIX + fn);
                f.remove();
                if (NekoGui::dataStore->active_routing == fn) {
                    NekoGui::Routing::SetToActive(NekoGui::Routing::List().first());
                    REFRESH_ACTIVE_ROUTING(NekoGui::dataStore->active_routing, NekoGui::dataStore->routing.get())
                }
                w->accept();
            }
        }
    });
    connect(cancel, &QPushButton::clicked, w, &QDialog::accept);
    connect(list, &QListWidget::itemDoubleClicked, this, [=](QListWidgetItem *item) {
        lineEdit->setText(item->text());
        emit load->clicked();
    });
    w->exec();
    w->deleteLater();
}
