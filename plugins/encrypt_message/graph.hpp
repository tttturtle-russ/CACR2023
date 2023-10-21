//
// Created by russ on 23-10-19.
//

#ifndef MOSQUITTO_MESSAGE_ENCRYPT_GRAPH_HPP
#define MOSQUITTO_MESSAGE_ENCRYPT_GRAPH_HPP
#include <boost/graph/adjacency_list.hpp>
#include <utility>
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
private:
    graph g;
    std::string owner;
public:
    explicit Graph():g(){};
    explicit Graph(std::string  _owner):owner(std::move(_owner)){};
    explicit Graph(const graph& _g,std::string _owner):g(_g),owner(std::move(_owner)){};
    Graph(const Graph& _g):g(_g.g),owner(_g.owner){};
    ~Graph(){g.clear();}
    graph::vertex_descriptor add_vertex(const std::string &name);
    void add_edge(graph::vertex_descriptor from, graph::vertex_descriptor to);
    void set_owner(const std::string &name);
    std::string get_owner();
    std::string get_vertex_name(const graph::vertex_descriptor &v);
    bool draw(const std::string &filename);
    void store(mongocxx::pool *pool);
};

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

bool Graph::draw(const std::string &filename) {
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
    auto nodes = (*client)->database("mqtt").collection("nodes");
    if (!nodes) {
        fprintf(stderr, "Failed to get collection.\n");
        return;
    }
    auto edges = (*client)->database("mqtt").collection("edges");
    if (!edges) {
        fprintf(stderr, "Failed to get collection.\n");
        return;
    }
    auto doc = bsoncxx::builder::stream::document{};
    doc << "owner" << this->owner;
    boost::num_vertices(this->g);
}

#endif //MOSQUITTO_MESSAGE_ENCRYPT_GRAPH_HPP
