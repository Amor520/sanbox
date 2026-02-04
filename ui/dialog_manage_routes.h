#pragma once

#include <QDialog>
#include <QMenu>

#include "3rdparty/qv2ray/v2/ui/QvAutoCompleteTextEdit.hpp"
#include "main/NekoGui.hpp"

QT_BEGIN_NAMESPACE
namespace Ui {
    class DialogManageRoutes;
}
QT_END_NAMESPACE

class DialogManageRoutes : public QDialog {
    Q_OBJECT

public:
    explicit DialogManageRoutes(QWidget *parent = nullptr);

    ~DialogManageRoutes() override;

private:
    Ui::DialogManageRoutes *ui;

    struct {
        QString custom_route;
        QString custom_route_global;
    } CACHE;

    struct SimpleRouteSnapshot {
        QString direct_ip;
        QString direct_domain;
        QString proxy_ip;
        QString proxy_domain;
        QString block_ip;
        QString block_domain;
        QString def_outbound;
        QString custom;
    };

    // "User 1" acts like a draft slot so switching presets won't wipe user edits.
    SimpleRouteSnapshot user1_snapshot;
    bool user1_snapshot_valid = false;
    bool preset_is_user1 = true;

    QMenu *builtInSchemesMenu;
    Qv2ray::ui::widgets::AutoCompleteTextEdit *directDomainTxt;
    Qv2ray::ui::widgets::AutoCompleteTextEdit *proxyDomainTxt;
    Qv2ray::ui::widgets::AutoCompleteTextEdit *blockDomainTxt;
    //
    Qv2ray::ui::widgets::AutoCompleteTextEdit *directIPTxt;
    Qv2ray::ui::widgets::AutoCompleteTextEdit *blockIPTxt;
    Qv2ray::ui::widgets::AutoCompleteTextEdit *proxyIPTxt;
    //
    NekoGui::Routing routing_cn_lan = NekoGui::Routing(1);
    NekoGui::Routing routing_global = NekoGui::Routing(0);
    //
    QString title_base;
    QString active_routing;

    void SaveSimpleRouteSnapshot(SimpleRouteSnapshot *out) const;

    void LoadSimpleRouteSnapshot(const SimpleRouteSnapshot &in);

    void LoadUser1DraftFromDataStore();

    void PersistUser1DraftToDataStore(bool saveNow);

public slots:

    void accept() override;

    QList<QAction *> getBuiltInSchemes();

    QAction *schemeToAction(const QString &name, const NekoGui::Routing &scheme);

    void UpdateDisplayRouting(NekoGui::Routing *conf, bool qv);

    void SaveDisplayRouting(NekoGui::Routing *conf);

    void on_load_save_clicked();
};
