//
// Created by russ on 23-10-19.
//

#ifndef MOSQUITTO_MESSAGE_ENCRYPT_GRAPH_HPP
#define MOSQUITTO_MESSAGE_ENCRYPT_GRAPH_HPP
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/iteration_macros.hpp>
#include <utility>
#include <filesystem>
#include <cairo/cairo.h>
#include <mongocxx/uri.hpp>
#include <mongocxx/pool.hpp>
#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/json.hpp>

struct vertex_info {
    std::string name;
    time_t timestamp{};
};

typedef boost::adjacency_list<boost::vecS, boost::vecS, boost::directedS,vertex_info> graph;

class Graph {
public:
    explicit Graph();
    explicit Graph(std::string  _owner):owner(std::move(_owner)){};
    explicit Graph(const graph& _g,std::string _owner):g(_g),owner(std::move(_owner)){};
    Graph(const Graph& _g);
    ~Graph();
    graph::vertex_descriptor add_vertex(const std::string &name);
    void add_edge(graph::vertex_descriptor from, graph::vertex_descriptor to);
    void set_owner(const std::string &name);
    graph get_graph();
    std::string get_owner();
    std::string get_vertex_name(const graph::vertex_descriptor &v);
    bool visualization(const std::string &filename);
    void store(mongocxx::pool *pool);
    void load(mongocxx::pool *pool);

private:
    graph g;
    std::string owner;
};

Graph::Graph() {
    this->g = graph();
    this->owner = "";
}

Graph::Graph(const Graph &_g) {
    this->g = _g.g;
    this->owner = _g.owner;
}

graph::vertex_descriptor Graph::add_vertex(const std::string &name) {
    vertex_info v_info;
    // 设置节点名称
    v_info.name = name;
    boost::add_vertex(this->g);
    // 设置节点时间戳
    v_info.timestamp = time(nullptr);
    return boost::add_vertex(v_info, this->g);
}

void Graph::add_edge(graph::vertex_descriptor from, graph::vertex_descriptor to) {
    boost::add_edge(from, to, this->g);
}

void Graph::set_owner(const std::string &name) {
    this->owner = name;
}

std::string Graph::get_owner() {
    return this->owner;
}

std::string Graph::get_vertex_name(const graph::vertex_descriptor &v) {
    return this->g[v].name;
}

bool Graph::visualization(const std::string &filename) {
    if (filename.empty()){
        fprintf(stderr,"No Such Path\n");
        return false;
    }
    auto surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 1920, 1080);
    auto cr = cairo_create(surface);
    // 画出背景，白色
    cairo_set_source_rgb(cr, 1, 1, 1);
    cairo_paint(cr);

    return cairo_surface_write_to_png(surface, filename.c_str()) == CAIRO_STATUS_SUCCESS;
}

void Graph::store(mongocxx::pool *pool) {
    auto client = pool->try_acquire();
    if (!client) {
        fprintf(stderr, "Failed to pop client from pool.\n");
        return;
    }
    auto graph_collection = (*client)->database("mqtt").collection("graph_collection");
    if (!graph_collection) {
        fprintf(stderr, "Failed to get collection.\n");
        return;
    }
    auto doc_builder = bsoncxx::builder::basic::document{};
    auto vertexs = bsoncxx::builder::basic::array{};
    BGL_FORALL_EDGES(e,this->g,graph){
        auto source = boost::source(e,this->g);
        auto target = boost::target(e,this->g);
        bsoncxx::builder::basic::document doc;
        doc.append(bsoncxx::builder::basic::kvp("source_vertex_name",this->g[source].name));
        doc.append(bsoncxx::builder::basic::kvp("source_vertex_time",bsoncxx::types::b_date{std::chrono::system_clock::from_time_t(this->g[source].timestamp)}));
        doc.append(bsoncxx::builder::basic::kvp("target_vertex_name",this->g[target].name));
        doc.append(bsoncxx::builder::basic::kvp("target_vertex_time",bsoncxx::types::b_date{std::chrono::system_clock::from_time_t(this->g[target].timestamp)}));
        vertexs.append(doc);
    }
    doc_builder.append(bsoncxx::builder::basic::kvp("owner",this->owner));
    doc_builder.append(bsoncxx::builder::basic::kvp("timestamp",bsoncxx::types::b_date{std::chrono::system_clock::now()}));
    doc_builder.append(bsoncxx::builder::basic::kvp("edges",vertexs));
    graph_collection.insert_one(doc_builder.view());
}

void Graph::load(mongocxx::pool *pool) {
    auto client = pool->try_acquire();
    if (!client) {
        fprintf(stderr, "Failed to pop client from pool.\n");
        return;
    }
    auto graph_collection = (*client)->database("mqtt").collection("graph_collection");
    if (!graph_collection) {
        fprintf(stderr, "Failed to get collection.\n");
        return;
    }
    auto doc = bsoncxx::builder::stream::document{};
    doc << "owner" << this->owner;
    auto cursor = graph_collection.find_one(doc.view());
    if (!cursor) {
        fprintf(stderr, "No Such Graph:%s\n",this->owner.c_str());
        return;
    }
    auto element = cursor->view()["edges"];
    if (!element) {
        fprintf(stderr, "No Such Graph:%s\n",this->owner.c_str());
        return;
    }
    auto array = element.get_array().value;
    for (const auto &item: array){
        auto source_vertex_name = item["source_vertex_name"].get_string().value.to_string();
        auto source_vertex_time = item["source_vertex_time"].get_date();
        auto target_vertex_name = item["target_vertex_name"].get_string().value.to_string();
        auto target_vertex_time = item["target_vertex_time"].get_date();
        auto source_vertex = this->add_vertex(source_vertex_name);
        auto target_vertex = this->add_vertex(target_vertex_name);
        this->add_edge(source_vertex,target_vertex);
        this->g[source_vertex].timestamp = std::chrono::system_clock::to_time_t(source_vertex_time);
        this->g[target_vertex].timestamp = std::chrono::system_clock::to_time_t(target_vertex_time);
    }
}

Graph::~Graph() {
    g.clear();
}

graph Graph::get_graph() {
    return this->g;
}


#endif //MOSQUITTO_MESSAGE_ENCRYPT_GRAPH_HPP
